package main

import (
    "flag"
    "log"
    "os"
    "os/signal"
    "sync"
    "sync/atomic"
    "syscall"
    "time"

    "github.com/espegro/nfs-trail/internal/aggregator"
    "github.com/espegro/nfs-trail/internal/config"
    "github.com/espegro/nfs-trail/internal/ebpf"
    "github.com/espegro/nfs-trail/internal/enrichment"
    "github.com/espegro/nfs-trail/internal/mounts"
    "github.com/espegro/nfs-trail/internal/output"
    "github.com/espegro/nfs-trail/internal/types"
)

// Stats tracks event processing statistics
type Stats struct {
    EventsReceived  uint64
    EventsProcessed uint64
    EventsDropped   uint64
    EventsFiltered  uint64
}

var (
    configPath = flag.String("config", "/etc/nfs-trail/nfs-trail.yaml", "Path to configuration file")
    debug      = flag.Bool("debug", false, "Enable debug mode (stdout output regardless of config)")
)

func main() {
    flag.Parse()

    log.Println("NFS Trail - Starting up...")

    // Load configuration
    cfg, err := loadConfiguration(*configPath)
    if err != nil {
        log.Fatalf("Failed to load configuration: %v", err)
    }

    // Set log level
    setupLogging(cfg.Logging.Level)

    // Create eBPF monitor first (needed for mount watcher callback)
    log.Println("Loading eBPF programs...")
    monitor, err := ebpf.NewMonitor()
    if err != nil {
        log.Fatalf("Failed to create eBPF monitor: %v", err)
    }
    defer monitor.Close()

    // Create mount watcher (checks every 5 seconds)
    mountWatcher := mounts.NewMountWatcher(5 * time.Second)

    // Register callback for mount changes
    mountWatcher.OnChange(func(newMounts map[uint64]mounts.MountInfo) {
        // Filter mounts based on config
        if !cfg.Mounts.All {
            newMounts = mounts.FilterMountsByPath(newMounts, cfg.Mounts.Paths)
        }
        // Update eBPF map
        if err := monitor.UpdateNFSMounts(mounts.GetDeviceIDMap(newMounts)); err != nil {
            log.Printf("Error updating NFS mounts map: %v", err)
        } else {
            log.Printf("Updated NFS mount filters (%d mounts)", len(newMounts))
        }
    })

    // Start mount watcher
    log.Println("Starting mount watcher...")
    if err := mountWatcher.Start(); err != nil {
        log.Fatalf("Failed to start mount watcher: %v", err)
    }
    defer mountWatcher.Stop()

    // Get initial mounts
    nfsMounts := mountWatcher.GetCurrentMounts()
    if len(nfsMounts) == 0 {
        log.Println("Warning: No NFS mounts detected")
    } else {
        log.Printf("Found %d NFS mount(s):", len(nfsMounts))
        for _, mount := range nfsMounts {
            log.Printf("  - %s on %s (type: %s, device_id: %d)",
                mount.Device, mount.Mountpoint, mount.FSType, mount.DeviceID)
        }
    }

    // Filter mounts based on config
    if !cfg.Mounts.All {
        nfsMounts = mounts.FilterMountsByPath(nfsMounts, cfg.Mounts.Paths)
        log.Printf("Filtered to %d mount(s) based on configuration", len(nfsMounts))
    }

    // Update NFS mounts map
    log.Println("Configuring NFS mount filters...")
    if err := monitor.UpdateNFSMounts(mounts.GetDeviceIDMap(nfsMounts)); err != nil {
        log.Fatalf("Failed to update NFS mounts map: %v", err)
    }

    // Note: UID filtering is done in userspace (not eBPF) to support large ranges
    log.Println("UID filtering configured (userspace)")

    // Attach kprobes
    log.Println("Attaching kprobes...")
    if err := monitor.AttachProbes(); err != nil {
        log.Fatalf("Failed to attach probes: %v", err)
    }

    // Start event reader
    log.Println("Starting event reader...")
    if err := monitor.StartEventReader(); err != nil {
        log.Fatalf("Failed to start event reader: %v", err)
    }

    // Create output logger based on configuration
    var logger output.Logger
    if *debug || cfg.Output.Type == "stdout" || cfg.Output.Type == "" {
        logger = output.NewStdoutLogger()
        log.Println("Output: stdout")
    } else if cfg.Output.Type == "file" {
        fileLogger, err := output.NewFileLogger(output.FileLoggerConfig{
            Path:       cfg.Output.File.Path,
            MaxSizeMB:  cfg.Output.File.MaxSizeMB,
            MaxBackups: cfg.Output.File.MaxBackups,
            MaxAgeDays: cfg.Output.File.MaxAgeDays,
            Compress:   cfg.Output.File.Compress,
        })
        if err != nil {
            log.Fatalf("Failed to create file logger: %v", err)
        }
        logger = fileLogger
        log.Printf("Output: file (%s, max %dMB, %d backups)",
            cfg.Output.File.Path, cfg.Output.File.MaxSizeMB, cfg.Output.File.MaxBackups)
    } else {
        log.Printf("Warning: Unknown output type '%s', using stdout", cfg.Output.Type)
        logger = output.NewStdoutLogger()
    }
    defer logger.Close()

    // Create user/group cache
    cacheTTL := time.Duration(cfg.Performance.Cache.TTLSeconds) * time.Second
    cacheSize := cfg.Performance.Cache.Size
    userGroupCache := enrichment.NewUserGroupCache(cacheTTL, cacheSize)
    log.Printf("User/group cache initialized (TTL: %v, size: %d)", cacheTTL, cacheSize)

    // Event channel (from eBPF) - use configurable buffer size
    bufferSize := cfg.Performance.ChannelBufferSize
    if bufferSize <= 0 {
        bufferSize = 1000 // Default fallback
    }
    eventChan := make(chan *types.FileEvent, bufferSize)

    // Output channel (to logger, can be FileEvent or AggregatedEvent)
    outputChan := make(chan interface{}, bufferSize)

    // Initialize stats
    var stats Stats

    // WaitGroup for graceful shutdown
    var wg sync.WaitGroup

    // Create aggregator if enabled
    var agg *aggregator.EventAggregator
    if cfg.Aggregation.Enabled {
        agg = aggregator.NewEventAggregator(
            cfg.Aggregation.WindowMS,
            cfg.Aggregation.MinEventCount,
            cfg.Aggregation.MaxFileList,
            outputChan,
        )
        log.Printf("Event aggregation enabled (window: %dms, min count: %d)",
            cfg.Aggregation.WindowMS, cfg.Aggregation.MinEventCount)
    }

    // Start event processor (enrichment and filtering)
    wg.Add(1)
    go func() {
        defer wg.Done()
        for event := range eventChan {
            atomic.AddUint64(&stats.EventsReceived, 1)

            // Apply UID filtering (userspace)
            if cfg.ShouldFilterUID(event.UID) {
                atomic.AddUint64(&stats.EventsFiltered, 1)
                continue // Skip this event
            }

            // Apply operation filtering
            if cfg.ShouldFilterOperation(event.Operation.String()) {
                atomic.AddUint64(&stats.EventsFiltered, 1)
                continue // Skip this event
            }

            // Enrich event with mount point (use current mounts from watcher)
            event.MountPoint = mounts.GetMountPointByDeviceID(mountWatcher.GetCurrentMounts(), event.DeviceID)

            // Enrich with username/groupname
            event.Username = userGroupCache.GetUsername(event.UID)
            event.Groupname = userGroupCache.GetGroupname(event.GID)

            // Send to aggregator or directly to output (non-blocking)
            if cfg.Aggregation.Enabled {
                agg.ProcessEvent(event)
                atomic.AddUint64(&stats.EventsProcessed, 1)
            } else {
                select {
                case outputChan <- event:
                    atomic.AddUint64(&stats.EventsProcessed, 1)
                default:
                    // Channel full, drop event
                    atomic.AddUint64(&stats.EventsDropped, 1)
                }
            }
        }

        // When event channel closes, flush aggregator and close output channel
        if cfg.Aggregation.Enabled {
            agg.Flush()
        }
        close(outputChan)
    }()

    // Start output processor (handles both individual and aggregated events)
    wg.Add(1)
    go func() {
        defer wg.Done()
        for item := range outputChan {
            switch v := item.(type) {
            case *types.FileEvent:
                // Individual event
                if err := logger.LogEvent(v); err != nil {
                    log.Printf("Error logging event: %v", err)
                }
            case *aggregator.AggregatedEvent:
                // Aggregated event
                duration := v.EndTime.Sub(v.StartTime).Nanoseconds()
                if err := logger.LogAggregatedEvent(v.Count, v.Files, v.FirstEvent, duration); err != nil {
                    log.Printf("Error logging aggregated event: %v", err)
                }
            }
        }
    }()

    // Handle signals
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

    log.Println("NFS Trail is running. Press Ctrl+C to stop.")

    // Start reading events in a goroutine
    go func() {
        if err := monitor.ReadEvents(eventChan); err != nil {
            log.Printf("Error reading events: %v", err)
        }
    }()

    // Start periodic stats logging if enabled
    var statsTicker *time.Ticker
    if cfg.Performance.StatsIntervalSec > 0 {
        statsTicker = time.NewTicker(time.Duration(cfg.Performance.StatsIntervalSec) * time.Second)
        go func() {
            for range statsTicker.C {
                received := atomic.LoadUint64(&stats.EventsReceived)
                processed := atomic.LoadUint64(&stats.EventsProcessed)
                dropped := atomic.LoadUint64(&stats.EventsDropped)
                filtered := atomic.LoadUint64(&stats.EventsFiltered)
                log.Printf("Stats: received=%d processed=%d filtered=%d dropped=%d",
                    received, processed, filtered, dropped)
            }
        }()
    }

    // Wait for signal
    <-sigChan
    log.Println("Shutting down...")

    // Stop stats ticker if running
    if statsTicker != nil {
        statsTicker.Stop()
    }

    // Close event channel to trigger shutdown of processor goroutines
    close(eventChan)

    // Wait for goroutines to finish processing remaining events
    log.Println("Waiting for event processors to finish...")
    wg.Wait()

    // Print final stats
    log.Printf("Final stats: received=%d processed=%d filtered=%d dropped=%d",
        atomic.LoadUint64(&stats.EventsReceived),
        atomic.LoadUint64(&stats.EventsProcessed),
        atomic.LoadUint64(&stats.EventsFiltered),
        atomic.LoadUint64(&stats.EventsDropped))
}

func loadConfiguration(path string) (*config.Config, error) {
    // Try to load from file
    cfg, err := config.LoadConfig(path)
    if err != nil {
        if os.IsNotExist(err) {
            log.Printf("Config file not found at %s, using defaults", path)
            return config.DefaultConfig(), nil
        }
        return nil, err
    }

    return cfg, nil
}

func setupLogging(level string) {
    // For now, just log everything
    // TODO: Implement proper log levels
    log.SetFlags(log.LstdFlags | log.Lshortfile)
}

package main

import (
    "flag"
    "fmt"
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
    "github.com/espegro/nfs-trail/internal/logger"
    "github.com/espegro/nfs-trail/internal/metrics"
    "github.com/espegro/nfs-trail/internal/mounts"
    "github.com/espegro/nfs-trail/internal/output"
    "github.com/espegro/nfs-trail/internal/types"
)

const version = "0.1.0"

// Stats tracks event processing statistics
type Stats struct {
    EventsReceived  uint64
    EventsProcessed uint64
    EventsDropped   uint64
    EventsFiltered  uint64
}

var (
    // Configuration
    configPath = flag.String("config", "/etc/nfs-trail/nfs-trail.yaml", "")
    noConfig   = flag.Bool("no-config", false, "")

    // Output modes
    simpleOutput = flag.Bool("simple", false, "")

    // Debug options (legacy and new)
    debugMode = flag.Bool("debug", false, "") // Legacy: alias for -simple -stats
    showStats = flag.Bool("stats", false, "")

    // Info
    showVersion = flag.Bool("version", false, "")
    showHelp    = flag.Bool("help", false, "")
)

func init() {
    // Custom usage function
    flag.Usage = printUsage
}

func printUsage() {
    fmt.Fprintf(os.Stderr, `
╔══════════════════════════════════════════════════════════════════════════════╗
║                              NFS TRAIL v%s                              ║
║                                                                              ║
║  A daemon for logging file operations on NFS-mounted filesystems using eBPF  ║
╚══════════════════════════════════════════════════════════════════════════════╝

USAGE:
    nfs-trail [OPTIONS]

DESCRIPTION:
    NFS Trail monitors file access on NFS mounts at the kernel level using eBPF.
    It captures read, write, and metadata operations, enriches them with user/group
    information, and outputs structured logs suitable for security auditing.

MODES:

    Production Mode (default):
        sudo nfs-trail -config /etc/nfs-trail/nfs-trail.yaml

        Uses configuration file to control filtering, aggregation, and output.
        Suitable for long-running daemon with systemd integration.

    Standalone Debug Mode:
        sudo nfs-trail -no-config -simple -stats

        Quick NFS troubleshooting without configuration file.
        Human-readable output with real-time statistics.

OPTIONS:

  Configuration:
    -config <path>
        Path to YAML configuration file.
        Default: /etc/nfs-trail/nfs-trail.yaml

    -no-config
        Run with built-in defaults, ignore configuration file.
        Useful for quick debugging without creating config.
        Default: false

  Output:
    -simple
        Use simple human-readable one-line output format.
        Example: "14:23:45 ✓ read    espen (1000)  cat    /mnt/nfs/file.txt 4.2 KB"
        Instead of JSON output.
        Default: false (JSON output)

  Monitoring:
    -debug
        Debug mode: enables both -simple and -stats.
        Useful for quick troubleshooting sessions.
        Default: false

    -stats
        Print statistics every 10 seconds (events received/processed/dropped).
        Useful for monitoring system load and filter effectiveness.
        Default: false

  Information:
    -version
        Show version information and exit.

    -help
        Show this help message and exit.

EXAMPLES:

    # Production use with systemd
    sudo systemctl start nfs-trail

    # Quick debugging session (legacy -debug flag)
    sudo nfs-trail -debug -config /tmp/nfs-trail.yaml

    # Quick debugging session (no config needed)
    sudo nfs-trail -no-config -simple -stats

    # Monitor specific config with human-readable output
    sudo nfs-trail -config /tmp/my-config.yaml -simple

    # Test with built-in defaults, JSON output
    sudo nfs-trail -no-config

REQUIREMENTS:

    Runtime:
        • Linux kernel 5.8+ with BTF enabled
        • Root privileges or CAP_BPF + CAP_PERFMON capabilities
        • Active NFS mounts (v3 or v4)

    Tested Platforms:
        • RHEL 9.x (kernel 5.14+)
        • Ubuntu 24.04 (kernel 6.8+)

CONFIGURATION:

    When using -config, the YAML file controls:
        • Which NFS mounts to monitor (all or specific paths)
        • UID/operation filtering (include/exclude rules)
        • Event aggregation (reduce log volume)
        • Output destination (file with rotation, stdout, journald)
        • Performance tuning (buffers, rate limits)
        • Prometheus metrics endpoint

    See /etc/nfs-trail/nfs-trail.yaml.example for full options.

    When using -no-config, sensible defaults are used:
        • Monitor all NFS mounts
        • Filter root (UID 0) and nobody (UID 65534)
        • Include UIDs 1000-60000
        • Enable event aggregation (500ms window)
        • Output to stdout (JSON format, or simple if -simple flag)

MORE INFO:

    GitHub:  https://github.com/espegro/nfs-trail
    Docs:    https://github.com/espegro/nfs-trail/blob/main/README.md
    Issues:  https://github.com/espegro/nfs-trail/issues

`, version)
}

func main() {
    flag.Parse()

    // Handle version flag
    if *showVersion {
        fmt.Printf("nfs-trail version %s\n", version)
        os.Exit(0)
    }

    // Handle help flag
    if *showHelp {
        printUsage()
        os.Exit(0)
    }

    log.Println("NFS Trail - Starting up...")

    // Handle legacy -debug flag (alias for -simple -stats)
    if *debugMode {
        *simpleOutput = true
        *showStats = true
    }

    // Load configuration based on flags
    var cfg *config.Config
    if *noConfig {
        log.Println("Using built-in default configuration (-no-config)")
        cfg = config.DefaultConfig()
    } else {
        var err error
        cfg, err = loadConfiguration(*configPath)
        if err != nil {
            log.Fatalf("[ERROR] Failed to load configuration: %v", err)
        }
    }

    // Apply flag overrides to config
    if *showStats {
        cfg.Performance.StatsIntervalSec = 10
    }

    // Initialize logging with configured level and output
    if err := setupLogging(cfg.Logging.Level, cfg.Logging.Output); err != nil {
        log.Fatalf("[ERROR] Failed to setup logging: %v", err)
    }

    logger.Info("NFS Trail daemon starting...")
    if *noConfig {
        logger.Info("Configuration: built-in defaults")
    } else {
        logger.Debug("Configuration loaded from %s", *configPath)
    }

    // Start Prometheus metrics server if enabled
    var metricsServer *metrics.Server
    if cfg.Metrics.Enabled {
        metricsServer = metrics.NewServer(cfg.Metrics.Port)
        if err := metricsServer.Start(); err != nil {
            logger.Error("Failed to start metrics server: %v", err)
            os.Exit(1)
        }
        logger.Info("Metrics server enabled on port %d", cfg.Metrics.Port)
    }

    // Create eBPF monitor first (needed for mount watcher callback)
    logger.Info("Loading eBPF programs...")
    monitor, err := ebpf.NewMonitor()
    if err != nil {
        logger.Error("Failed to create eBPF monitor: %v", err)
        os.Exit(1)
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
            logger.Info("Error updating NFS mounts map: %v", err)
        } else {
            logger.Info("Updated NFS mount filters (%d mounts)", len(newMounts))
            metrics.MountsMonitored.Set(float64(len(newMounts)))
        }
    })

    // Start mount watcher
    logger.Info("Starting mount watcher...")
    if err := mountWatcher.Start(); err != nil {
        logger.Error("Failed to start mount watcher: %v", err)
        os.Exit(1)
    }
    defer mountWatcher.Stop()

    // Get initial mounts
    nfsMounts := mountWatcher.GetCurrentMounts()
    if len(nfsMounts) == 0 {
        logger.Info("Warning: No NFS mounts detected")
    } else {
        logger.Info("Found %d NFS mount(s):", len(nfsMounts))
        for _, mount := range nfsMounts {
            logger.Info("  - %s on %s (type: %s, device_id: %d)",
                mount.Device, mount.Mountpoint, mount.FSType, mount.DeviceID)
        }
    }

    // Filter mounts based on config
    if !cfg.Mounts.All {
        nfsMounts = mounts.FilterMountsByPath(nfsMounts, cfg.Mounts.Paths)
        logger.Info("Filtered to %d mount(s) based on configuration", len(nfsMounts))
    }

    // Update NFS mounts map
    logger.Info("Configuring NFS mount filters...")
    if err := monitor.UpdateNFSMounts(mounts.GetDeviceIDMap(nfsMounts)); err != nil {
        logger.Error("Failed to update NFS mounts map: %v", err)
        os.Exit(1)
    }
    metrics.MountsMonitored.Set(float64(len(nfsMounts)))

    // Note: UID filtering is done in userspace (not eBPF) to support large ranges
    logger.Info("UID filtering configured (userspace)")

    // Attach kprobes
    logger.Info("Attaching kprobes...")
    if err := monitor.AttachProbes(); err != nil {
        logger.Error("Failed to attach probes: %v", err)
        os.Exit(1)
    }

    // Start event reader
    logger.Info("Starting event reader...")
    if err := monitor.StartEventReader(); err != nil {
        logger.Error("Failed to start event reader: %v", err)
        os.Exit(1)
    }

    // Create output logger based on configuration and flags
    var outputLogger output.Logger
    if *simpleOutput {
        // Simple human-readable output (overrides config)
        outputLogger = output.NewSimpleLogger()
        logger.Info("Output: simple (human-readable one-line format)")
        // Disable aggregation for simple output (makes more sense)
        if cfg.Aggregation.Enabled {
            logger.Info("Note: Aggregation disabled for simple output mode")
            cfg.Aggregation.Enabled = false
        }
    } else if cfg.Output.Type == "stdout" || cfg.Output.Type == "" {
        outputLogger = output.NewStdoutLogger()
        logger.Info("Output: stdout (JSON)")
    } else if cfg.Output.Type == "file" {
        fileLogger, err := output.NewFileLogger(output.FileLoggerConfig{
            Path:       cfg.Output.File.Path,
            MaxSizeMB:  cfg.Output.File.MaxSizeMB,
            MaxBackups: cfg.Output.File.MaxBackups,
            MaxAgeDays: cfg.Output.File.MaxAgeDays,
            Compress:   cfg.Output.File.Compress,
        })
        if err != nil {
            logger.Error("Failed to create file logger: %v", err)
            os.Exit(1)
        }
        outputLogger = fileLogger
        logger.Info("Output: file (%s, max %dMB, %d backups)",
            cfg.Output.File.Path, cfg.Output.File.MaxSizeMB, cfg.Output.File.MaxBackups)
    } else {
        logger.Info("Warning: Unknown output type '%s', using stdout", cfg.Output.Type)
        outputLogger = output.NewStdoutLogger()
    }
    defer outputLogger.Close()

    // Create user/group cache
    cacheTTL := time.Duration(cfg.Performance.Cache.TTLSeconds) * time.Second
    cacheSize := cfg.Performance.Cache.Size
    userGroupCache := enrichment.NewUserGroupCache(cacheTTL, cacheSize)
    logger.Info("User/group cache initialized (TTL: %v, size: %d)", cacheTTL, cacheSize)

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
        logger.Info("Event aggregation enabled (window: %dms, min count: %d)",
            cfg.Aggregation.WindowMS, cfg.Aggregation.MinEventCount)
    }

    // Start event processor (enrichment and filtering)
    wg.Add(1)
    go func() {
        defer wg.Done()
        for event := range eventChan {
            atomic.AddUint64(&stats.EventsReceived, 1)
            metrics.EventsReceived.Inc()

            // Apply UID filtering (userspace)
            if cfg.ShouldFilterUID(event.UID) {
                atomic.AddUint64(&stats.EventsFiltered, 1)
                metrics.EventsFiltered.Inc()
                continue // Skip this event
            }

            // Apply operation filtering
            if cfg.ShouldFilterOperation(event.Operation.String()) {
                atomic.AddUint64(&stats.EventsFiltered, 1)
                metrics.EventsFiltered.Inc()
                continue // Skip this event
            }

            // Enrich event with mount point (use current mounts from watcher)
            event.MountPoint = mounts.GetMountPointByDeviceID(mountWatcher.GetCurrentMounts(), event.DeviceID)

            // Enrich with username/groupname
            event.Username = userGroupCache.GetUsername(event.UID)
            event.Groupname = userGroupCache.GetGroupname(event.GID)

            // Record operation metrics (ReturnValue contains bytes for read/write)
            metrics.RecordOperation(event.Operation.String(), event.ReturnValue)

            // Send to aggregator or directly to output (non-blocking)
            if cfg.Aggregation.Enabled {
                agg.ProcessEvent(event)
                atomic.AddUint64(&stats.EventsProcessed, 1)
                metrics.EventsProcessed.Inc()
            } else {
                select {
                case outputChan <- event:
                    atomic.AddUint64(&stats.EventsProcessed, 1)
                    metrics.EventsProcessed.Inc()
                default:
                    // Channel full, drop event
                    atomic.AddUint64(&stats.EventsDropped, 1)
                    metrics.EventsDropped.Inc()
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
                if err := outputLogger.LogEvent(v); err != nil {
                    logger.Info("Error logging event: %v", err)
                }
            case *aggregator.AggregatedEvent:
                // Aggregated event
                duration := v.EndTime.Sub(v.StartTime).Nanoseconds()
                if err := outputLogger.LogAggregatedEvent(v.Count, v.TotalBytes, v.Files, v.FirstEvent, duration); err != nil {
                    logger.Info("Error logging aggregated event: %v", err)
                }
            }
        }
    }()

    // Handle signals
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

    logger.Info("NFS Trail is running. Press Ctrl+C to stop.")

    // Start reading events in a goroutine
    go func() {
        if err := monitor.ReadEvents(eventChan); err != nil {
            logger.Info("Error reading events: %v", err)
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
    logger.Info("Shutting down...")

    // Stop stats ticker if running
    if statsTicker != nil {
        statsTicker.Stop()
    }

    // Close event channel to trigger shutdown of processor goroutines
    close(eventChan)

    // Wait for goroutines to finish processing remaining events
    logger.Info("Waiting for event processors to finish...")
    wg.Wait()

    // Stop metrics server if running
    if metricsServer != nil {
        if err := metricsServer.Stop(); err != nil {
            logger.Warn("Error stopping metrics server: %v", err)
        }
    }

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
            // Use log instead of logger (not initialized yet)
            log.Printf("Config file not found at %s, using defaults", path)
            return config.DefaultConfig(), nil
        }
        return nil, err
    }

    return cfg, nil
}

func setupLogging(level string, output string) error {
    // Initialize structured logger with configured level and output
    if err := logger.Init(level, output); err != nil {
        return err
    }

    // Keep standard log for libraries that use it
    log.SetFlags(log.LstdFlags)

    return nil
}

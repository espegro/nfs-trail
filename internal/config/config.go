package config

import (
    "fmt"
    "os"

    "gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
    Mounts      MountsConfig      `yaml:"mounts"`
    Filters     FiltersConfig     `yaml:"filters"`
    Aggregation AggregationConfig `yaml:"aggregation"`
    Output      OutputConfig      `yaml:"output"`
    Performance PerformanceConfig `yaml:"performance"`
    Logging     LoggingConfig     `yaml:"logging"`
    Metrics     MetricsConfig     `yaml:"metrics"`
}

// MountsConfig specifies which NFS mounts to monitor
type MountsConfig struct {
    All   bool     `yaml:"all"`
    Paths []string `yaml:"paths"`
}

// FiltersConfig specifies UID/GID and operation filtering rules
type FiltersConfig struct {
    IncludeUIDs       []uint32   `yaml:"include_uids"`
    ExcludeUIDs       []uint32   `yaml:"exclude_uids"`
    IncludeUIDRanges  []UIDRange `yaml:"include_uid_ranges"`
    ExcludeUIDRanges  []UIDRange `yaml:"exclude_uid_ranges"`
    ExcludeOperations []string   `yaml:"exclude_operations"` // e.g., ["stat", "read"]
    IncludeOperations []string   `yaml:"include_operations"` // if set, only these are logged
}

// UIDRange represents a range of UIDs
type UIDRange struct {
    Min uint32 `yaml:"min"`
    Max uint32 `yaml:"max"`
}

// AggregationConfig controls event aggregation
type AggregationConfig struct {
    Enabled       bool `yaml:"enabled"`
    WindowMS      int  `yaml:"window_ms"`
    MaxFileList   int  `yaml:"max_file_list"`
    MinEventCount int  `yaml:"min_event_count"`
}

// OutputConfig specifies output settings
type OutputConfig struct {
    Type   string           `yaml:"type"` // file, stdout, journald
    File   FileOutputConfig `yaml:"file"`
    ECS    ECSConfig        `yaml:"ecs"`
}

// FileOutputConfig for file-based output
type FileOutputConfig struct {
    Path        string `yaml:"path"`
    MaxSizeMB   int    `yaml:"max_size_mb"`
    MaxBackups  int    `yaml:"max_backups"`
    MaxAgeDays  int    `yaml:"max_age_days"`
    Compress    bool   `yaml:"compress"`
}

// ECSConfig for Elastic Common Schema settings
type ECSConfig struct {
    Version string   `yaml:"version"`
    Tags    []string `yaml:"tags"`
}

// PerformanceConfig for performance tuning
type PerformanceConfig struct {
    Cache                CacheConfig `yaml:"cache"`
    ChannelBufferSize    int         `yaml:"channel_buffer_size"`     // Event channel buffer
    StatsIntervalSec     int         `yaml:"stats_interval_sec"`      // Print stats every N seconds (0 = disabled)
    MaxEventsPerSec      int         `yaml:"max_events_per_sec"`      // Max events/sec (0 = unlimited)
    DropPolicy           string      `yaml:"drop_policy"`             // "oldest" or "newest"
    LogDroppedEvents     bool        `yaml:"log_dropped_events"`      // Log when events are dropped
    DropStatsIntervalSec int         `yaml:"drop_stats_interval_sec"` // Log drop stats every N seconds (0 = disabled)
}

// CacheConfig for user/group name caching
type CacheConfig struct {
    Size       int `yaml:"size"`
    TTLSeconds int `yaml:"ttl_seconds"`
}

// LoggingConfig for daemon's own logging
type LoggingConfig struct {
    Level  string `yaml:"level"`  // debug, info, warn, error
    Output string `yaml:"output"` // stdout, stderr, file
}

// MetricsConfig for Prometheus metrics
type MetricsConfig struct {
    Enabled bool `yaml:"enabled"` // Enable Prometheus metrics endpoint
    Port    int  `yaml:"port"`    // HTTP port for /metrics endpoint
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
    return &Config{
        Mounts: MountsConfig{
            All:   true,
            Paths: []string{},
        },
        Filters: FiltersConfig{
            IncludeUIDs:      []uint32{},
            ExcludeUIDs:      []uint32{0, 65534}, // root and nobody
            IncludeUIDRanges: []UIDRange{{Min: 1000, Max: 60000}},
            ExcludeUIDRanges: []UIDRange{},
        },
        Aggregation: AggregationConfig{
            Enabled:       true,
            WindowMS:      500,
            MaxFileList:   10,
            MinEventCount: 3,
        },
        Output: OutputConfig{
            Type: "stdout",
            File: FileOutputConfig{
                Path:       "/var/log/nfs-trail/events.json",
                MaxSizeMB:  100,
                MaxBackups: 10,
                MaxAgeDays: 30,
                Compress:   true,
            },
            ECS: ECSConfig{
                Version: "8.17.0",
                Tags:    []string{"nfs", "filesystem", "audit"},
            },
        },
        Performance: PerformanceConfig{
            ChannelBufferSize:    10000, // Large buffer for bursts
            StatsIntervalSec:     0,     // Disabled by default
            MaxEventsPerSec:      0,     // Unlimited by default
            DropPolicy:           "oldest",
            LogDroppedEvents:     true,
            DropStatsIntervalSec: 30, // Log drop stats every 30 seconds
            Cache: CacheConfig{
                Size:       10000,
                TTLSeconds: 300, // 5 minutes
            },
        },
        Logging: LoggingConfig{
            Level:  "info",
            Output: "stdout",
        },
        Metrics: MetricsConfig{
            Enabled: false,
            Port:    9090,
        },
    }
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("reading config file: %w", err)
    }

    cfg := DefaultConfig()
    if err := yaml.Unmarshal(data, cfg); err != nil {
        return nil, fmt.Errorf("parsing config file: %w", err)
    }

    return cfg, nil
}

// ShouldFilterUID checks if a UID should be filtered (excluded from logging)
// Returns true if the UID should be filtered out (not logged)
func (c *Config) ShouldFilterUID(uid uint32) bool {
    // Check explicit excludes first
    for _, excludeUID := range c.Filters.ExcludeUIDs {
        if uid == excludeUID {
            return true // Filter out
        }
    }

    // Check exclude ranges
    for _, r := range c.Filters.ExcludeUIDRanges {
        if uid >= r.Min && uid <= r.Max {
            return true // Filter out
        }
    }

    // If no includes specified, allow all (except already-excluded above)
    hasIncludes := len(c.Filters.IncludeUIDs) > 0 || len(c.Filters.IncludeUIDRanges) > 0
    if !hasIncludes {
        return false // Don't filter, allow
    }

    // Check explicit includes
    for _, includeUID := range c.Filters.IncludeUIDs {
        if uid == includeUID {
            return false // Don't filter, allow
        }
    }

    // Check include ranges
    for _, r := range c.Filters.IncludeUIDRanges {
        if uid >= r.Min && uid <= r.Max {
            return false // Don't filter, allow
        }
    }

    // Has includes but UID not in them - filter out
    return true
}

// ShouldFilterOperation checks if an operation should be filtered
// Returns true if the operation should be filtered out (not logged)
func (c *Config) ShouldFilterOperation(operation string) bool {
    // Check explicit excludes first
    for _, excludeOp := range c.Filters.ExcludeOperations {
        if operation == excludeOp {
            return true // Filter out
        }
    }

    // If no includes specified, allow all (except already-excluded above)
    if len(c.Filters.IncludeOperations) == 0 {
        return false // Don't filter, allow
    }

    // Check if operation is in include list
    for _, includeOp := range c.Filters.IncludeOperations {
        if operation == includeOp {
            return false // Don't filter, allow
        }
    }

    // Has includes but operation not in them - filter out
    return true
}

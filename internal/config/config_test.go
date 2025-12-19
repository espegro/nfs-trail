package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	// Verify defaults
	if !cfg.Mounts.All {
		t.Error("Expected Mounts.All to be true by default")
	}

	if cfg.Output.Type != "stdout" {
		t.Errorf("Expected Output.Type to be 'stdout', got '%s'", cfg.Output.Type)
	}

	if !cfg.Aggregation.Enabled {
		t.Error("Expected Aggregation.Enabled to be true by default")
	}

	if cfg.Performance.ChannelBufferSize != 1000 {
		t.Errorf("Expected ChannelBufferSize 1000, got %d", cfg.Performance.ChannelBufferSize)
	}
}

func TestLoadConfig(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "test-config.yaml")

	yamlContent := `
mounts:
  all: false
  paths:
    - /mnt/nfs1
    - /mnt/nfs2

filters:
  exclude_uids: [0, 65534]
  include_uid_ranges:
    - min: 1000
      max: 2000
  exclude_operations:
    - stat

aggregation:
  enabled: true
  window_ms: 1000
  min_event_count: 5

output:
  type: file
  file:
    path: /var/log/test.json
    max_size_mb: 50
    compress: true

performance:
  channel_buffer_size: 2000
  stats_interval_sec: 30
`

	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Verify parsed values
	if cfg.Mounts.All {
		t.Error("Expected Mounts.All to be false")
	}

	if len(cfg.Mounts.Paths) != 2 {
		t.Errorf("Expected 2 mount paths, got %d", len(cfg.Mounts.Paths))
	}

	if cfg.Aggregation.WindowMS != 1000 {
		t.Errorf("Expected WindowMS 1000, got %d", cfg.Aggregation.WindowMS)
	}

	if cfg.Output.Type != "file" {
		t.Errorf("Expected Output.Type 'file', got '%s'", cfg.Output.Type)
	}

	if cfg.Output.File.MaxSizeMB != 50 {
		t.Errorf("Expected MaxSizeMB 50, got %d", cfg.Output.File.MaxSizeMB)
	}

	if cfg.Performance.ChannelBufferSize != 2000 {
		t.Errorf("Expected ChannelBufferSize 2000, got %d", cfg.Performance.ChannelBufferSize)
	}
}

func TestShouldFilterUID(t *testing.T) {
	cfg := &Config{
		Filters: FiltersConfig{
			ExcludeUIDs: []uint32{0, 65534},
			IncludeUIDRanges: []UIDRange{
				{Min: 1000, Max: 2000},
			},
		},
	}

	tests := []struct {
		uid      uint32
		expected bool
		name     string
	}{
		{0, true, "root excluded"},
		{65534, true, "nobody excluded"},
		{1000, false, "1000 in include range"},
		{1500, false, "1500 in include range"},
		{2000, false, "2000 in include range"},
		{500, true, "500 not in include range"},
		{3000, true, "3000 not in include range"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cfg.ShouldFilterUID(tt.uid)
			if result != tt.expected {
				t.Errorf("ShouldFilterUID(%d) = %v, want %v", tt.uid, result, tt.expected)
			}
		})
	}
}

func TestShouldFilterUID_NoIncludes(t *testing.T) {
	// When no includes specified, only excludes should filter
	cfg := &Config{
		Filters: FiltersConfig{
			ExcludeUIDs: []uint32{0},
		},
	}

	if cfg.ShouldFilterUID(0) != true {
		t.Error("Expected UID 0 to be filtered (excluded)")
	}

	if cfg.ShouldFilterUID(1000) != false {
		t.Error("Expected UID 1000 to NOT be filtered (no includes, not excluded)")
	}
}

func TestShouldFilterUID_ExplicitInclude(t *testing.T) {
	cfg := &Config{
		Filters: FiltersConfig{
			IncludeUIDs: []uint32{1000, 1001},
			ExcludeUIDs: []uint32{0},
		},
	}

	if cfg.ShouldFilterUID(1000) != false {
		t.Error("Expected UID 1000 to NOT be filtered (explicitly included)")
	}

	if cfg.ShouldFilterUID(1001) != false {
		t.Error("Expected UID 1001 to NOT be filtered (explicitly included)")
	}

	if cfg.ShouldFilterUID(2000) != true {
		t.Error("Expected UID 2000 to be filtered (not in include list)")
	}
}

func TestShouldFilterOperation(t *testing.T) {
	cfg := &Config{
		Filters: FiltersConfig{
			ExcludeOperations: []string{"stat", "read"},
		},
	}

	tests := []struct {
		operation string
		expected  bool
		name      string
	}{
		{"stat", true, "stat excluded"},
		{"read", true, "read excluded"},
		{"write", false, "write not excluded"},
		{"delete", false, "delete not excluded"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cfg.ShouldFilterOperation(tt.operation)
			if result != tt.expected {
				t.Errorf("ShouldFilterOperation(%s) = %v, want %v", tt.operation, result, tt.expected)
			}
		})
	}
}

func TestShouldFilterOperation_IncludeOnly(t *testing.T) {
	cfg := &Config{
		Filters: FiltersConfig{
			IncludeOperations: []string{"write", "delete"},
		},
	}

	if cfg.ShouldFilterOperation("write") != false {
		t.Error("Expected 'write' to NOT be filtered (in include list)")
	}

	if cfg.ShouldFilterOperation("delete") != false {
		t.Error("Expected 'delete' to NOT be filtered (in include list)")
	}

	if cfg.ShouldFilterOperation("read") != true {
		t.Error("Expected 'read' to be filtered (not in include list)")
	}

	if cfg.ShouldFilterOperation("stat") != true {
		t.Error("Expected 'stat' to be filtered (not in include list)")
	}
}

func TestLoadConfig_InvalidFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Expected error loading nonexistent config file")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "bad-config.yaml")

	badYAML := `
mounts:
  all: true
  invalid syntax here
    - broken
`

	if err := os.WriteFile(cfgPath, []byte(badYAML), 0644); err != nil {
		t.Fatalf("Failed to write bad config: %v", err)
	}

	_, err := LoadConfig(cfgPath)
	if err == nil {
		t.Error("Expected error loading invalid YAML")
	}
}

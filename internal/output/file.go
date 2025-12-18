package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/espen/nfs-trail/internal/types"
	"gopkg.in/natefinch/lumberjack.v2"
)

// FileLogger writes events to a file with rotation support
type FileLogger struct {
	logger  *lumberjack.Logger
	encoder *json.Encoder
	mu      sync.Mutex
}

// FileLoggerConfig holds configuration for the file logger
type FileLoggerConfig struct {
	Path       string
	MaxSizeMB  int
	MaxBackups int
	MaxAgeDays int
	Compress   bool
}

// NewFileLogger creates a new file logger with rotation
func NewFileLogger(cfg FileLoggerConfig) (*FileLogger, error) {
	// Ensure directory exists
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating log directory %s: %w", dir, err)
	}

	// Set defaults if not specified
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 100
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 10
	}
	if cfg.MaxAgeDays <= 0 {
		cfg.MaxAgeDays = 30
	}

	logger := &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSizeMB, // megabytes
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAgeDays, // days
		Compress:   cfg.Compress,
		LocalTime:  true,
	}

	return &FileLogger{
		logger:  logger,
		encoder: json.NewEncoder(logger),
	}, nil
}

// LogEvent writes a file event to the log file
func (l *FileLogger) LogEvent(event *types.FileEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	output := map[string]interface{}{
		"@timestamp": event.Timestamp.Format("2006-01-02T15:04:05.000Z07:00"),
		"event": map[string]interface{}{
			"kind":   "event",
			"action": fmt.Sprintf("nfs-file-%s", event.Operation.String()),
		},
		"file": map[string]interface{}{
			"path":   event.Filename,
			"name":   event.Filename,
			"inode":  fmt.Sprintf("%d", event.Inode),
			"device": fmt.Sprintf("%d", event.DeviceID),
		},
		"process": map[string]interface{}{
			"pid":  event.PID,
			"name": event.Comm,
		},
		"user": map[string]interface{}{
			"id":   fmt.Sprintf("%d", event.UID),
			"name": event.Username,
		},
		"group": map[string]interface{}{
			"id":   fmt.Sprintf("%d", event.GID),
			"name": event.Groupname,
		},
		"nfs": map[string]interface{}{
			"mount_point": event.MountPoint,
			"operation": map[string]interface{}{
				"type":  event.Operation.String(),
				"bytes": event.ReturnValue,
			},
		},
	}

	return l.encoder.Encode(output)
}

// LogAggregatedEvent writes an aggregated event to the log file
func (l *FileLogger) LogAggregatedEvent(count int, files []string, firstEvent *types.FileEvent, duration int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Create file list summary
	fileList := files
	hasMore := false
	if len(files) > 10 {
		fileList = files[:10]
		hasMore = true
	}

	fileListStr := strings.Join(fileList, ", ")
	if hasMore {
		fileListStr += fmt.Sprintf(" ... (+%d more)", len(files)-10)
	}

	output := map[string]interface{}{
		"@timestamp": firstEvent.Timestamp.Format("2006-01-02T15:04:05.000Z07:00"),
		"event": map[string]interface{}{
			"kind":     "event",
			"action":   fmt.Sprintf("nfs-file-%s-aggregated", firstEvent.Operation.String()),
			"duration": duration,
		},
		"file": map[string]interface{}{
			"device": fmt.Sprintf("%d", firstEvent.DeviceID),
		},
		"process": map[string]interface{}{
			"pid":  firstEvent.PID,
			"name": firstEvent.Comm,
		},
		"user": map[string]interface{}{
			"id":   fmt.Sprintf("%d", firstEvent.UID),
			"name": firstEvent.Username,
		},
		"group": map[string]interface{}{
			"id":   fmt.Sprintf("%d", firstEvent.GID),
			"name": firstEvent.Groupname,
		},
		"nfs": map[string]interface{}{
			"mount_point": firstEvent.MountPoint,
			"operation": map[string]interface{}{
				"type":  firstEvent.Operation.String(),
				"count": count,
			},
		},
		"aggregation": map[string]interface{}{
			"enabled":    true,
			"file_count": len(files),
			"files":      fileListStr,
		},
	}

	return l.encoder.Encode(output)
}

// Close closes the file logger
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.logger.Close()
}

// Rotate forces a log rotation
func (l *FileLogger) Rotate() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.logger.Rotate()
}

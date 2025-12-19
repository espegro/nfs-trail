package output

import "github.com/espegro/nfs-trail/internal/types"

// Logger is the interface for event loggers
type Logger interface {
	// LogEvent logs a single file event
	LogEvent(event *types.FileEvent) error

	// LogAggregatedEvent logs an aggregated event
	LogAggregatedEvent(count int, totalBytes int64, files []string, firstEvent *types.FileEvent, duration int64) error

	// Close closes the logger and flushes any buffered data
	Close() error
}

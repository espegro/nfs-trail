package output

import (
	"fmt"
	"path/filepath"

	"github.com/espegro/nfs-trail/internal/types"
)

// SimpleLogger writes events in human-readable one-line format
// Designed for debugging and quick NFS troubleshooting
type SimpleLogger struct {
	headerPrinted bool
}

// NewSimpleLogger creates a new simple logger
func NewSimpleLogger() *SimpleLogger {
	return &SimpleLogger{
		headerPrinted: false,
	}
}

// printHeader prints the column headers
func (l *SimpleLogger) printHeader() {
	if !l.headerPrinted {
		fmt.Println("──────────────────────────────────────────────────────────────────────────────")
		fmt.Printf("%-8s %-1s %-8s %-16s %-7s %-10s %s\n",
			"TIME", "✓", "OP", "USER", "UID", "PROCESS", "PATH [BYTES/ERROR]")
		fmt.Println("──────────────────────────────────────────────────────────────────────────────")
		l.headerPrinted = true
	}
}

// LogEvent writes a single event as a human-readable one-liner
func (l *SimpleLogger) LogEvent(event *types.FileEvent) error {
	l.printHeader()

	timestamp := event.Timestamp.Format("15:04:05")

	// Success indicator
	success := "✓"
	statusDetail := ""
	if event.ReturnValue < 0 {
		success = "✗"
		statusDetail = fmt.Sprintf(" [%s]", getErrorName(event.ReturnValue))
	}

	// Build full path
	fullPath := event.Filename
	if event.MountPoint != "" && event.Filename != "" {
		fullPath = filepath.Join(event.MountPoint, event.Filename)
	}

	// Format bytes nicely
	bytesStr := ""
	if event.Operation.String() == "read" || event.Operation.String() == "write" {
		if event.ReturnValue >= 0 {
			bytesStr = fmt.Sprintf(" %s", formatBytes(event.ReturnValue))
		}
	}

	// Print one-liner
	fmt.Printf("%s %s %-8s %-16s (%-5d) %-10s %s%s%s\n",
		timestamp,
		success,
		event.Operation.String(),
		truncateString(event.Username, 16),
		event.UID,
		truncateString(event.Comm, 10),
		fullPath,
		bytesStr,
		statusDetail,
	)

	return nil
}

// LogAggregatedEvent writes an aggregated event summary
// Note: SimpleLogger is typically used with aggregation disabled
func (l *SimpleLogger) LogAggregatedEvent(count int, totalBytes int64, files []string, firstEvent *types.FileEvent, duration int64) error {
	l.printHeader()

	timestamp := firstEvent.Timestamp.Format("15:04:05")

	// Format duration
	durationMs := float64(duration) / 1_000_000

	// Build summary
	summary := fmt.Sprintf("%d files", len(files))
	if totalBytes > 0 {
		summary = fmt.Sprintf("%d files, %s", len(files), formatBytes(totalBytes))
	}

	fmt.Printf("%s ⊕ %-8s %-16s (%-5d) %-10s [AGGREGATED: %d ops, %s in %.1fms]\n",
		timestamp,
		firstEvent.Operation.String(),
		truncateString(firstEvent.Username, 16),
		firstEvent.UID,
		truncateString(firstEvent.Comm, 10),
		count,
		summary,
		durationMs,
	)

	return nil
}

// Close closes the logger (noop for simple output)
func (l *SimpleLogger) Close() error {
	return nil
}

// getErrorName converts errno to string name
func getErrorName(errno int64) string {
	switch errno {
	case -1:
		return "EPERM"
	case -2:
		return "ENOENT"
	case -13:
		return "EACCES"
	case -17:
		return "EEXIST"
	case -28:
		return "ENOSPC"
	case -122:
		return "EDQUOT"
	default:
		return fmt.Sprintf("ERR:%d", -errno)
	}
}

// formatBytes formats byte count in human-readable format
func formatBytes(bytes int64) string {
	if bytes < 0 {
		return ""
	}

	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// truncateString truncates a string to maxLen, adding ... if truncated
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

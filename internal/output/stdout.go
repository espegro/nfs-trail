package output

import (
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/espegro/nfs-trail/internal/types"
)

// StdoutLogger writes events to stdout in JSON format
type StdoutLogger struct {
    encoder *json.Encoder
}

// NewStdoutLogger creates a new stdout logger
func NewStdoutLogger() *StdoutLogger {
    return &StdoutLogger{
        encoder: json.NewEncoder(os.Stdout),
    }
}

// LogEvent writes a file event to stdout as JSON
func (l *StdoutLogger) LogEvent(event *types.FileEvent) error {
    // Build full path from mount point + filename
    fullPath := event.Filename
    if event.MountPoint != "" && event.Filename != "" {
        fullPath = filepath.Join(event.MountPoint, event.Filename)
    }

    // Create a simple JSON representation
    output := map[string]interface{}{
        "@timestamp": event.Timestamp.Format("2006-01-02T15:04:05.000Z07:00"),
        "event": map[string]interface{}{
            "kind":   "event",
            "action": fmt.Sprintf("nfs-file-%s", event.Operation.String()),
        },
        "file": map[string]interface{}{
            "path":   fullPath,
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

// LogAggregatedEvent writes an aggregated event to stdout as JSON
func (l *StdoutLogger) LogAggregatedEvent(count int, totalBytes int64, files []string, firstEvent *types.FileEvent, duration int64) error {
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
            "duration": duration, // in nanoseconds
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
                "bytes": totalBytes,
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

// Close closes the logger (noop for stdout)
func (l *StdoutLogger) Close() error {
    return nil
}

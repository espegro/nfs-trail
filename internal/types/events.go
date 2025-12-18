package types

import "time"

// OperationType represents the type of file operation
type OperationType uint32

const (
    OpRead     OperationType = 1
    OpWrite    OperationType = 2
    OpOpen     OperationType = 3
    OpClose    OperationType = 4
    OpStat     OperationType = 5
    OpChmod    OperationType = 6
    OpChown    OperationType = 7
    OpRename   OperationType = 8
    OpDelete   OperationType = 9
    OpMkdir    OperationType = 10
    OpRmdir    OperationType = 11
    OpSymlink  OperationType = 12
    OpLink     OperationType = 13
    OpSetxattr OperationType = 14
)

// String returns the string representation of an operation type
func (o OperationType) String() string {
    switch o {
    case OpRead:
        return "read"
    case OpWrite:
        return "write"
    case OpOpen:
        return "open"
    case OpClose:
        return "close"
    case OpStat:
        return "stat"
    case OpChmod:
        return "chmod"
    case OpChown:
        return "chown"
    case OpRename:
        return "rename"
    case OpDelete:
        return "delete"
    case OpMkdir:
        return "mkdir"
    case OpRmdir:
        return "rmdir"
    case OpSymlink:
        return "symlink"
    case OpLink:
        return "link"
    case OpSetxattr:
        return "setxattr"
    default:
        return "unknown"
    }
}

// FileEvent represents a file operation event from eBPF
type FileEvent struct {
    TimestampNS uint64
    PID         uint32
    TID         uint32
    UID         uint32
    GID         uint32
    Inode       uint64
    DeviceID    uint64
    Operation   OperationType
    ReturnValue int64
    Flags       uint32
    Comm        string
    Filename    string
    // Enriched fields (populated in userspace)
    Username   string
    Groupname  string
    Timestamp  time.Time
    MountPoint string
}

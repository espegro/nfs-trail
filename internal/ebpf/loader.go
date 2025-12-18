package ebpf

import (
    "bytes"
    "encoding/binary"
    "errors"
    "fmt"
    "log"
    "time"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/espen/nfs-trail/internal/types"
)

// Monitor manages the eBPF programs and maps
type Monitor struct {
    objs             *nfsMonitorObjects
    links            []link.Link
    reader           *ringbuf.Reader
    nfsMountsMap     *ebpf.Map
    uidFilterMap     *ebpf.Map
    eventsRingBuf    *ebpf.Map
    currentDeviceIDs map[uint64]bool // Track current device IDs for cleanup
}

// NewMonitor creates a new eBPF monitor
func NewMonitor() (*Monitor, error) {
    // Load eBPF objects
    objs := &nfsMonitorObjects{}
    if err := loadNfsMonitorObjects(objs, nil); err != nil {
        return nil, fmt.Errorf("loading eBPF objects: %w", err)
    }

    m := &Monitor{
        objs:             objs,
        nfsMountsMap:     objs.NfsMounts,
        uidFilterMap:     objs.UidFilter,
        eventsRingBuf:    objs.Events,
        currentDeviceIDs: make(map[uint64]bool),
    }

    return m, nil
}

// AttachProbes attaches kprobes to kernel functions
func (m *Monitor) AttachProbes() error {
    // Attach vfs_read kprobe entry
    kp, err := link.Kprobe("vfs_read", m.objs.TraceVfsReadEntry, nil)
    if err != nil {
        return fmt.Errorf("attaching kprobe to vfs_read: %w", err)
    }
    m.links = append(m.links, kp)
    log.Println("Attached kprobe to vfs_read")

    // Attach vfs_read kretprobe
    kretprobe, err := link.Kretprobe("vfs_read", m.objs.TraceVfsReadReturn, nil)
    if err != nil {
        return fmt.Errorf("attaching kretprobe to vfs_read: %w", err)
    }
    m.links = append(m.links, kretprobe)
    log.Println("Attached kretprobe to vfs_read")

    // Attach vfs_write kprobe
    kpWrite, err := link.Kprobe("vfs_write", m.objs.TraceVfsWriteEntry, nil)
    if err != nil {
        log.Printf("Warning: failed to attach kprobe to vfs_write: %v", err)
    } else {
        m.links = append(m.links, kpWrite)
        log.Println("Attached kprobe to vfs_write")
    }

    // Attach vfs_write kretprobe
    kretprobeWrite, err := link.Kretprobe("vfs_write", m.objs.TraceVfsWriteReturn, nil)
    if err != nil {
        log.Printf("Warning: failed to attach kretprobe to vfs_write: %v", err)
    } else {
        m.links = append(m.links, kretprobeWrite)
        log.Println("Attached kretprobe to vfs_write")
    }

    // Attach vfs_getattr kprobe (for stat/ls operations)
    kpGetattr, err := link.Kprobe("vfs_getattr", m.objs.TraceVfsGetattrEntry, nil)
    if err != nil {
        log.Printf("Warning: failed to attach kprobe to vfs_getattr: %v", err)
    } else {
        m.links = append(m.links, kpGetattr)
        log.Println("Attached kprobe to vfs_getattr")
    }

    // Also attach vfs_getattr_nosec as fallback
    kpGetattrNosec, err := link.Kprobe("vfs_getattr_nosec", m.objs.TraceVfsGetattrEntry, nil)
    if err != nil {
        log.Printf("Warning: failed to attach kprobe to vfs_getattr_nosec: %v", err)
    } else {
        m.links = append(m.links, kpGetattrNosec)
        log.Println("Attached kprobe to vfs_getattr_nosec")
    }

    // Attach vfs_rename kprobe (for file/directory renaming)
    kpRename, err := link.Kprobe("vfs_rename", m.objs.TraceVfsRenameEntry, nil)
    if err != nil {
        log.Printf("Warning: failed to attach kprobe to vfs_rename: %v", err)
    } else {
        m.links = append(m.links, kpRename)
        log.Println("Attached kprobe to vfs_rename")
    }

    // Attach vfs_mkdir kprobe (for directory creation)
    kpMkdir, err := link.Kprobe("vfs_mkdir", m.objs.TraceVfsMkdirEntry, nil)
    if err != nil {
        log.Printf("Warning: failed to attach kprobe to vfs_mkdir: %v", err)
    } else {
        m.links = append(m.links, kpMkdir)
        log.Println("Attached kprobe to vfs_mkdir")
    }

    // Attach vfs_rmdir kprobe (for directory removal)
    kpRmdir, err := link.Kprobe("vfs_rmdir", m.objs.TraceVfsRmdirEntry, nil)
    if err != nil {
        log.Printf("Warning: failed to attach kprobe to vfs_rmdir: %v", err)
    } else {
        m.links = append(m.links, kpRmdir)
        log.Println("Attached kprobe to vfs_rmdir")
    }

    // Attach notify_change kprobe (for chmod/chown operations)
    kpSetattr, err := link.Kprobe("notify_change", m.objs.TraceVfsSetattrEntry, nil)
    if err != nil {
        log.Printf("Warning: failed to attach kprobe to notify_change: %v", err)
    } else {
        m.links = append(m.links, kpSetattr)
        log.Println("Attached kprobe to notify_change")
    }

    // Attach vfs_symlink kprobe (for symbolic link creation)
    kpSymlink, err := link.Kprobe("vfs_symlink", m.objs.TraceVfsSymlinkEntry, nil)
    if err != nil {
        log.Printf("Warning: failed to attach kprobe to vfs_symlink: %v", err)
    } else {
        m.links = append(m.links, kpSymlink)
        log.Println("Attached kprobe to vfs_symlink")
    }

    // Attach vfs_link kprobe (for hard link creation)
    kpLink, err := link.Kprobe("vfs_link", m.objs.TraceVfsLinkEntry, nil)
    if err != nil {
        log.Printf("Warning: failed to attach kprobe to vfs_link: %v", err)
    } else {
        m.links = append(m.links, kpLink)
        log.Println("Attached kprobe to vfs_link")
    }

    // Attach vfs_setxattr kprobe (for extended attribute manipulation)
    kpSetxattr, err := link.Kprobe("vfs_setxattr", m.objs.TraceVfsSetxattrEntry, nil)
    if err != nil {
        log.Printf("Warning: failed to attach kprobe to vfs_setxattr: %v", err)
    } else {
        m.links = append(m.links, kpSetxattr)
        log.Println("Attached kprobe to vfs_setxattr")
    }

    // Attach vfs_unlink kprobe (for file deletion)
    // This is NFS-filtered in eBPF so it won't generate noise from local filesystems
    kpUnlink, err := link.Kprobe("vfs_unlink", m.objs.TraceVfsUnlinkEntry, nil)
    if err != nil {
        log.Printf("Warning: failed to attach kprobe to vfs_unlink: %v", err)
    } else {
        m.links = append(m.links, kpUnlink)
        log.Println("Attached kprobe to vfs_unlink")
    }

    return nil
}

// StartEventReader starts reading events from the ring buffer
func (m *Monitor) StartEventReader() error {
    rd, err := ringbuf.NewReader(m.eventsRingBuf)
    if err != nil {
        return fmt.Errorf("opening ring buffer reader: %w", err)
    }
    m.reader = rd
    return nil
}

// ReadEvents reads events from the ring buffer and sends them to the channel
func (m *Monitor) ReadEvents(eventChan chan<- *types.FileEvent) error {
    if m.reader == nil {
        return errors.New("event reader not started")
    }

    for {
        record, err := m.reader.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                return nil
            }
            return fmt.Errorf("reading from ring buffer: %w", err)
        }

        // Parse the event
        event, err := parseEvent(record.RawSample)
        if err != nil {
            log.Printf("Error parsing event: %v", err)
            continue
        }

        // Send to channel
        select {
        case eventChan <- event:
        case <-time.After(1 * time.Second):
            log.Println("Event channel full, dropping event")
        }
    }
}

// parseEvent parses a raw event from the ring buffer
func parseEvent(data []byte) (*types.FileEvent, error) {
    if len(data) < 8+4+4+4+4+8+8+4+8+4 {
        return nil, fmt.Errorf("event data too short: %d bytes", len(data))
    }

    event := &types.FileEvent{}

    // Parse binary data (must match the C struct layout)
    buf := bytes.NewReader(data)

    binary.Read(buf, binary.LittleEndian, &event.TimestampNS)
    binary.Read(buf, binary.LittleEndian, &event.PID)
    binary.Read(buf, binary.LittleEndian, &event.TID)
    binary.Read(buf, binary.LittleEndian, &event.UID)
    binary.Read(buf, binary.LittleEndian, &event.GID)
    binary.Read(buf, binary.LittleEndian, &event.Inode)
    binary.Read(buf, binary.LittleEndian, &event.DeviceID)
    binary.Read(buf, binary.LittleEndian, &event.Operation)

    // Skip 4 bytes of padding (for alignment of int64 return_value)
    var padding uint32
    binary.Read(buf, binary.LittleEndian, &padding)

    binary.Read(buf, binary.LittleEndian, &event.ReturnValue)
    binary.Read(buf, binary.LittleEndian, &event.Flags)

    // Read comm (16 bytes, null-terminated)
    comm := make([]byte, 16)
    buf.Read(comm)
    event.Comm = nullTerminatedString(comm)

    // Read filename (256 bytes, null-terminated)
    filename := make([]byte, 256)
    buf.Read(filename)
    event.Filename = nullTerminatedString(filename)

    // Convert timestamp to time.Time
    // bpf_ktime_get_ns() returns nanoseconds since boot, not epoch
    // We need to use a different approach for absolute time
    event.Timestamp = time.Now() // For now, use current time

    return event, nil
}

// nullTerminatedString converts a null-terminated byte slice to a string
func nullTerminatedString(b []byte) string {
    n := bytes.IndexByte(b, 0)
    if n == -1 {
        return string(b)
    }
    return string(b[:n])
}

// UpdateNFSMounts updates the NFS mounts map
func (m *Monitor) UpdateNFSMounts(deviceIDs map[uint64]bool) error {
    // Remove device IDs that are no longer in the new set
    for oldDevID := range m.currentDeviceIDs {
        if _, exists := deviceIDs[oldDevID]; !exists {
            if err := m.nfsMountsMap.Delete(oldDevID); err != nil {
                // Ignore "not found" errors
                log.Printf("Note: could not delete device %d from map: %v", oldDevID, err)
            }
        }
    }

    // Add/update device IDs
    for devID, shouldMonitor := range deviceIDs {
        var val uint8
        if shouldMonitor {
            val = 1
        } else {
            val = 0
        }

        log.Printf("Adding device ID %d (0x%x) to eBPF map (monitor=%v)", devID, devID, shouldMonitor)
        if err := m.nfsMountsMap.Put(devID, val); err != nil {
            return fmt.Errorf("updating nfs_mounts map for device %d: %w", devID, err)
        }
    }

    // Update tracked device IDs
    m.currentDeviceIDs = make(map[uint64]bool)
    for devID := range deviceIDs {
        m.currentDeviceIDs[devID] = true
    }

    return nil
}

// UpdateUIDFilter updates the UID filter map
func (m *Monitor) UpdateUIDFilter(uids map[uint32]bool) error {
    for uid, allowed := range uids {
        var val uint8
        if allowed {
            val = 1
        } else {
            val = 0
        }

        if err := m.uidFilterMap.Put(uid, val); err != nil {
            return fmt.Errorf("updating uid_filter map for UID %d: %w", uid, err)
        }
    }

    return nil
}

// Close closes the monitor and cleans up resources
func (m *Monitor) Close() error {
    // Close ring buffer reader
    if m.reader != nil {
        if err := m.reader.Close(); err != nil {
            log.Printf("Error closing ring buffer reader: %v", err)
        }
    }

    // Detach all links
    for _, l := range m.links {
        if err := l.Close(); err != nil {
            log.Printf("Error closing link: %v", err)
        }
    }

    // Close eBPF objects
    if m.objs != nil {
        m.objs.Close()
    }

    return nil
}

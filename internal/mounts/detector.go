package mounts

import (
    "bufio"
    "bytes"
    "fmt"
    "os"
    "strings"

    "golang.org/x/sys/unix"
)

// MountInfo holds information about a mounted filesystem
type MountInfo struct {
    Device     string // e.g., "192.168.1.10:/export/data"
    Mountpoint string // e.g., "/mnt/nfs-storage"
    FSType     string // e.g., "nfs4"
    DeviceID   uint64 // Device ID from statfs
}

// DetectNFSMounts parses /proc/mounts and returns NFS mounts
func DetectNFSMounts() (map[uint64]MountInfo, error) {
    mounts := make(map[uint64]MountInfo)

    // Read /proc/mounts
    data, err := os.ReadFile("/proc/mounts")
    if err != nil {
        return nil, fmt.Errorf("reading /proc/mounts: %w", err)
    }

    scanner := bufio.NewScanner(bytes.NewReader(data))
    for scanner.Scan() {
        fields := strings.Fields(scanner.Text())
        if len(fields) < 3 {
            continue
        }

        device := fields[0]
        mountpoint := fields[1]
        fstype := fields[2]

        // Check if this is an NFS filesystem
        if !strings.HasPrefix(fstype, "nfs") {
            continue
        }

        // Get device ID via stat (st_dev)
        // This is what the kernel uses to identify filesystems
        var statbuf unix.Stat_t
        if err := unix.Stat(mountpoint, &statbuf); err != nil {
            // Skip mounts we can't stat (might be unmounted or permission issues)
            continue
        }

        // Device ID is st_dev from stat
        // This matches what the kernel uses in VFS layer
        devID := uint64(statbuf.Dev)

        mounts[devID] = MountInfo{
            Device:     device,
            Mountpoint: mountpoint,
            FSType:     fstype,
            DeviceID:   devID,
        }
    }

    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("scanning /proc/mounts: %w", err)
    }

    return mounts, nil
}

// FilterMountsByPath filters mounts based on a list of mountpoint prefixes
// If paths is empty, all mounts are returned
func FilterMountsByPath(mounts map[uint64]MountInfo, paths []string) map[uint64]MountInfo {
    // If no filter, return all
    if len(paths) == 0 {
        return mounts
    }

    filtered := make(map[uint64]MountInfo)
    for devID, mount := range mounts {
        for _, path := range paths {
            if strings.HasPrefix(mount.Mountpoint, path) {
                filtered[devID] = mount
                break
            }
        }
    }

    return filtered
}

// GetDeviceIDMap converts a map of MountInfo to a map of device IDs (all set to true)
func GetDeviceIDMap(mounts map[uint64]MountInfo) map[uint64]bool {
    devMap := make(map[uint64]bool)
    for devID := range mounts {
        devMap[devID] = true
    }
    return devMap
}

// GetMountPointByDeviceID returns the mountpoint for a given device ID
func GetMountPointByDeviceID(mounts map[uint64]MountInfo, deviceID uint64) string {
    if mount, ok := mounts[deviceID]; ok {
        return mount.Mountpoint
    }
    return ""
}

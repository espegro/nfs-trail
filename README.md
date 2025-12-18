# nfs-trail

A daemon for logging file operations on NFS-mounted filesystems using eBPF.

## Overview

nfs-trail monitors file access on NFS mounts at the kernel level using eBPF kprobes. It captures read, write, and metadata operations, enriches them with user/group information, and outputs JSON logs suitable for security auditing and compliance.

## Features

- Monitors NFSv3 and NFSv4 mounts
- Captures: read, write, stat, chmod, chown, rename, delete, mkdir, rmdir, symlink, link, setxattr
- Tracks actual bytes read/written
- Event aggregation reduces log volume
- User/group name resolution with caching
- Configurable UID and operation filtering
- JSON output (ECS-aligned) to file or stdout
- Log rotation support
- Portable binary via BPF CO-RE

## Requirements

### Build

- Go 1.21+
- Clang 14+
- LLVM 14+
- bpftool
- Linux headers

### Runtime

- Linux kernel 5.8+ with BTF enabled
- Root privileges or CAP_BPF + CAP_PERFMON

### Tested Platforms

- RHEL 9.x (kernel 5.14+)
- Ubuntu 24.04 (kernel 6.8+)

## Building

```
make clean && make
```

## Installation

```
sudo ./install.sh
```

The install script handles:
- Binary installation to /usr/local/bin
- Configuration directory setup
- Systemd service installation
- SELinux policy on RHEL (if enabled)
- Log directory creation

## Configuration

Configuration file: `/etc/nfs-trail/nfs-trail.yaml`

### Example

```yaml
mounts:
  all: true

filters:
  exclude_uids: [0, 65534]
  include_uid_ranges:
    - min: 1000
      max: 60000
  exclude_operations:
    - stat

aggregation:
  enabled: true
  window_ms: 500
  min_event_count: 3

output:
  type: file
  file:
    path: /var/log/nfs-trail/events.json
    max_size_mb: 100
    max_backups: 10
    compress: true

performance:
  channel_buffer_size: 1000
  stats_interval_sec: 60
```

### Options

**mounts**
- `all`: Monitor all NFS mounts
- `paths`: List of specific mount paths

**filters**
- `include_uids` / `exclude_uids`: UID whitelist/blacklist
- `include_uid_ranges` / `exclude_uid_ranges`: UID range filters
- `include_operations` / `exclude_operations`: Operation filters

**aggregation**
- `enabled`: Group similar events
- `window_ms`: Aggregation time window
- `min_event_count`: Minimum events to aggregate

**output**
- `type`: `stdout` or `file`
- `file.path`: Log file location
- `file.max_size_mb`: Size before rotation
- `file.max_backups`: Rotated files to keep
- `file.compress`: Gzip rotated files

## Usage

```
# Manual
sudo nfs-trail -config /etc/nfs-trail/nfs-trail.yaml

# Systemd
sudo systemctl start nfs-trail
sudo systemctl status nfs-trail
journalctl -u nfs-trail -f
```

## Output Format

JSON with ECS-aligned schema:

```json
{
  "@timestamp": "2025-12-18T19:17:45.242+01:00",
  "event": {"action": "nfs-file-read"},
  "file": {"name": "document.pdf", "inode": "11612665226"},
  "process": {"pid": 1234, "name": "cat"},
  "user": {"id": "1000", "name": "espen"},
  "nfs": {
    "mount_point": "/remote/storage",
    "operation": {"type": "read", "bytes": 670852}
  }
}
```

## Troubleshooting

**No events logged**
- Verify NFS mounts: `mount | grep nfs`
- Check BTF support: `ls /sys/kernel/btf/vmlinux`
- Check service status: `systemctl status nfs-trail`

**Permission denied**
- Run as root or grant capabilities: `setcap cap_bpf,cap_perfmon+ep nfs-trail`

**SELinux blocking (RHEL)**
- Check denials: `ausearch -m avc -ts recent`
- The install script creates a policy module; reinstall if needed

## Architecture

```
eBPF kprobes (kernel) --> Ring Buffer --> Go userspace --> JSON output
     |
     v
  VFS layer
  - vfs_read/write
  - vfs_getattr
  - notify_change
  - vfs_unlink
  - ...
```

## Performance

- eBPF overhead: ~500ns per event
- Memory: ~20MB resident
- Log reduction with aggregation: 10-100x

## Limitations

**Path Resolution**: Only the filename (basename) is captured in eBPF due to kernel stack limits (512 bytes) and verifier constraints. The full path shown in logs is `mount_point + filename`. Subdirectory paths are not captured.

Example: A file at `/mnt/nfs/subdir/deep/file.txt` will be logged as `/mnt/nfs/file.txt`.

For full path auditing, consider supplementing with auditd or using inode-based correlation.

## License

GPL-2.0 (required for eBPF)

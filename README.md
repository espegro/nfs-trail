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
- Rate limiting with configurable drop policies
- Prometheus metrics endpoint for monitoring
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
  channel_buffer_size: 10000
  max_events_per_sec: 0
  drop_policy: "oldest"
  log_dropped_events: true
  drop_stats_interval_sec: 30
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

**performance (rate limiting)**
- `channel_buffer_size`: Event buffer size (default: 10000)
  - Large buffer handles I/O bursts (e.g., `ls -R`, `rsync`)
- `max_events_per_sec`: Rate limit (0 = unlimited)
  - Set to prevent overwhelming system under extreme load
- `drop_policy`: `"oldest"` or `"newest"`
  - `oldest`: Drop old events to preserve recent activity (default)
  - `newest`: Drop new events to preserve existing data
- `log_dropped_events`: Log warnings when events are dropped (default: true)
  - **Critical for audit trail** - you must know when data is lost
- `drop_stats_interval_sec`: Log drop statistics every N seconds (default: 30)
  - Shows drop rate percentage for monitoring

**metrics (Prometheus integration)**
- `enabled`: Enable Prometheus metrics HTTP endpoint (default: false)
- `port`: HTTP port for /metrics endpoint (default: 9090)

### Prometheus Metrics

When enabled, nfs-trail exposes Prometheus metrics on `http://localhost:9090/metrics`.

**Available metrics:**
- `nfstrail_events_received_total` - Total events received from eBPF
- `nfstrail_events_processed_total` - Total events successfully processed
- `nfstrail_events_filtered_total` - Total events filtered (UID/operation filters)
- `nfstrail_events_dropped_total` - Total events dropped (buffer/rate limits)
- `nfstrail_operations_total{operation}` - Operations by type (read, write, etc.)
- `nfstrail_bytes_read_total` - Total bytes read from NFS
- `nfstrail_bytes_written_total` - Total bytes written to NFS
- `nfstrail_cache_lookups_total{result}` - Cache lookups (hit/miss)
- `nfstrail_mounts_monitored` - Number of NFS mounts currently monitored
- `nfstrail_event_processing_duration_seconds` - Event processing latency histogram

**Example Prometheus scrape config:**
```yaml
scrape_configs:
  - job_name: 'nfs-trail'
    static_configs:
      - targets: ['localhost:9090']
```

**Example queries:**
```
# Event throughput (events/sec)
rate(nfstrail_events_received_total[5m])

# Drop rate percentage
rate(nfstrail_events_dropped_total[5m]) / rate(nfstrail_events_received_total[5m]) * 100

# Top operations by frequency
topk(5, rate(nfstrail_operations_total[5m]))

# NFS bandwidth (bytes/sec)
rate(nfstrail_bytes_read_total[5m]) + rate(nfstrail_bytes_written_total[5m])

# Cache hit rate
rate(nfstrail_cache_lookups_total{result="hit"}[5m]) /
rate(nfstrail_cache_lookups_total[5m]) * 100
```

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

**Path Resolution**: Up to 4 parent directory levels are captured in eBPF. The full path shown in logs is `mount_point + relative_path`. For deeply nested paths (more than 4 levels from the mount root), only the deepest 4 directories plus filename are captured.

Example: A file at `/mnt/nfs/a/b/c/d/e/file.txt` will be logged as `/mnt/nfs/b/c/d/e/file.txt` (missing `a/`).

## License

GPL-2.0 (required for eBPF)

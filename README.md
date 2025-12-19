# nfs-trail

A daemon for logging file operations on NFS-mounted filesystems using eBPF.

## Overview

nfs-trail monitors file access on NFS mounts at the kernel level using eBPF kprobes. It captures read, write, and metadata operations, enriches them with user/group information, and outputs JSON logs suitable for security auditing and compliance.

## Features

- **Standalone debug mode**: Run without config for quick NFS troubleshooting
- **Monitors NFSv3 and NFSv4 mounts** at kernel level
- **Captures 15 operation types**: read, write, open, close, stat, chmod, chown, rename, delete, mkdir, rmdir, symlink, link, setxattr, truncate
- **Tracks bytes and errors**: Actual bytes read/written, file truncation, and operation failures
- **Event aggregation**: Reduces log volume by 10-100x
- **User/group resolution**: Cached lookups with configurable TTL
- **Flexible filtering**: UID ranges and operation type filters
- **Multiple output formats**: JSON (ECS-aligned), human-readable one-liner, or file with rotation
- **Prometheus metrics**: Failed operations, throughput, cache hit rate
- **Safe defaults**: Works out-of-the-box for debugging
- **Portable binary**: BPF CO-RE for kernel compatibility

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

## Download Pre-built Binary

**Latest Release: v0.5.0**

```bash
# Download binary
wget https://github.com/espegro/nfs-trail/raw/main/releases/v0.5.0/nfs-trail-v0.5.0-linux-amd64

# Verify checksum
wget https://github.com/espegro/nfs-trail/raw/main/releases/v0.5.0/nfs-trail-v0.5.0-linux-amd64.sha256
sha256sum -c nfs-trail-v0.5.0-linux-amd64.sha256

# Make executable
chmod +x nfs-trail-v0.5.0-linux-amd64

# Install with full system setup
wget https://github.com/espegro/nfs-trail/raw/main/install.sh
chmod +x install.sh
sudo ./install.sh -b nfs-trail-v0.5.0-linux-amd64
```

See [releases/v0.5.0/](releases/v0.5.0/) for more details.

## Building from Source

```bash
# Clone repository
git clone https://github.com/espegro/nfs-trail.git
cd nfs-trail

# Build
make clean && make
```

## Installation

### From Pre-built Binary

```bash
# After downloading binary (see above)
sudo ./install.sh -b nfs-trail-v0.5.0-linux-amd64
```

### From Source

```bash
# After building (see above)
sudo ./install.sh
```

The install script handles:
- Binary installation to /usr/local/bin
- Configuration directory setup (/etc/nfs-trail/)
- Systemd service installation
- SELinux policy on RHEL (if enabled)
- Log directory creation (/var/log/nfs-trail/)

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
- `nfstrail_operations_failed_total{operation,error}` - Failed operations by type and error code (EACCES, ENOENT, etc.)
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

# Failed operations rate (permission errors, file not found, etc.)
rate(nfstrail_operations_failed_total[5m])

# Top error types by frequency
topk(5, rate(nfstrail_operations_failed_total[5m]))

# Permission denied errors (potential scanning/unauthorized access attempts)
rate(nfstrail_operations_failed_total{error="EACCES"}[5m])

# File not found errors
rate(nfstrail_operations_failed_total{error="ENOENT"}[5m])

# Disk quota exceeded errors
rate(nfstrail_operations_failed_total{error="EDQUOT"}[5m])
```

## Usage

### Production Mode

For long-running daemon with systemd:

```bash
# Start with systemd
sudo systemctl start nfs-trail
sudo systemctl status nfs-trail
journalctl -u nfs-trail -f

# Or manually with config
sudo nfs-trail -config /etc/nfs-trail/nfs-trail.yaml
```

### Standalone Mode

Quick NFS troubleshooting without configuration file:

```bash
# Human-readable debug output
sudo nfs-trail -debug
sudo nfs-trail -debug -uid 1000

# JSON output for testing/parsing
sudo nfs-trail -no-config
sudo nfs-trail -no-config -uid 1000 -stats

# Example output (with -debug or -simple):
# ──────────────────────────────────────────────────────────────────────────────
# TIME     ✓ OP       USER             UID     PROCESS    PATH [BYTES/ERROR]
# ──────────────────────────────────────────────────────────────────────────────
# 14:23:45 ✓ read     espen            (1000)  cat        /mnt/nfs/data/file.txt 4.2 KB
# 14:23:47 ✗ open     alice            (1001)  vim        /mnt/nfs/docs/secret.doc [EACCES]
# 14:23:50 ✓ write    bob              (1002)  rsync      /mnt/nfs/backup/data.tar 128.5 MB
```

### Command-Line Options

```bash
# Show help
./nfs-trail -help

# Quick debug mode (human-readable output)
sudo nfs-trail -debug
sudo nfs-trail -debug -uid 1000

# JSON output for testing
sudo nfs-trail -no-config
sudo nfs-trail -no-config -uid 1000 -stats

# Use specific config
sudo nfs-trail -config /tmp/debug.yaml
sudo nfs-trail -config /tmp/debug.yaml -simple
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

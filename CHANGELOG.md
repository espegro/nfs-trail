# Changelog

All notable changes to nfs-trail will be documented in this file.

## [0.5.0] - 2025-12-19

### 🔒 Security

**Critical security hardening release** - All users should upgrade immediately.

- **[H1]** Fixed path traversal vulnerability in file output configuration
  - Added whitelist validation for log file paths
  - Only allows `/var/log/nfs-trail/`, `/tmp/nfs-trail/`, `/var/tmp/nfs-trail/`
  - Prevents directory traversal attacks via config files

- **[H2]** Added config file size limit (1MB) to prevent DoS attacks
  - Protects against billion laughs and deeply nested YAML attacks
  - Prevents memory exhaustion via malicious config files

- **[H3]** Implemented NSS lookup timeout (2 seconds)
  - Prevents daemon from blocking on slow LDAP/NIS backends
  - Ensures system remains responsive under all conditions
  - Falls back to `uid:N` / `gid:N` format on timeout

- **[M4]** Fixed log injection vulnerability
  - Sanitizes filenames to prevent fake log entry injection
  - Escapes control characters (\n, \r, \t) in all output formats
  - Protects against attackers using filenames with newlines

### ✨ Features

- **Standalone debug mode** - Run without configuration file
  - New `-debug` flag for quick troubleshooting
  - New `-simple` flag for human-readable output
  - New `-uid` flag to filter events from specific user
  - New `-stats` flag for real-time statistics
  - New `-no-config` flag to use built-in defaults

- **Human-readable output format**
  - SimpleLogger with column-aligned output
  - Success/failure indicators (✓/✗)
  - Human-friendly byte formatting (KB/MB/GB)
  - Error code display (EACCES, ENOENT, etc.)

- **Enhanced help system**
  - Professional ASCII box header
  - Concise, focused on common use cases
  - Real-world examples with context
  - Clear documentation of all options

- **Additional file operations**
  - Added `open` operation tracking
  - Added `close` operation tracking
  - Added `truncate` operation tracking
  - Total: 15 operation types monitored

### 📊 Monitoring

- **Failed operations tracking**
  - New Prometheus metric: `nfstrail_operations_failed_total{operation,error}`
  - Tracks permission denied (EACCES), file not found (ENOENT), etc.
  - JSON output includes `"success": true/false` field
  - Example queries for suspicious activity detection

- **Aggregated events now track total bytes**
  - Fixed missing `totalBytes` field in aggregated events
  - Shows cumulative data transfer for grouped operations

### 🐛 Bug Fixes

- Fixed logger initialization bug in loadConfiguration
- Fixed `-debug` flag to work standalone without `-no-config`
- Fixed aggregation auto-disable for simple output mode

### 📚 Documentation

- Added comprehensive `SECURITY_AUDIT.md` with full vulnerability analysis
- Updated README with new features and usage examples
- Added CHANGELOG.md for version tracking
- Improved inline code documentation with security comments

### 🔧 Internal Improvements

- Added `sanitizeString()` helper for log injection prevention
- Added `isFlagPassed()` helper for intelligent flag handling
- Improved flag precedence: command-line > config > defaults
- Better error messages with context

### 🎯 Breaking Changes

None - fully backward compatible with 0.1.0

### 📦 Migration Guide

No migration needed. Simply replace the binary and restart the service:

```bash
make clean && make
sudo systemctl restart nfs-trail
```

For users with custom configs, verify log output paths are under allowed directories.

---

## [0.1.0] - 2025-12-18

Initial release with basic NFS monitoring capabilities.

### Features
- eBPF-based NFS operation monitoring
- 12 operation types tracked
- Event aggregation
- User/group name resolution with caching
- JSON output (ECS-aligned)
- Prometheus metrics
- Configurable UID/operation filtering
- Log rotation support

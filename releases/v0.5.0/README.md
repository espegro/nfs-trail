# NFS Trail v0.5.0 Release

**Release Date**: 2025-12-19

## Download

- **Binary**: `nfs-trail-v0.5.0-linux-amd64`
- **Checksum**: `nfs-trail-v0.5.0-linux-amd64.sha256`

## Platform

- **Architecture**: x86_64 (amd64)
- **OS**: Linux
- **Kernel**: 5.8+ with BTF enabled
- **Tested on**:
  - RHEL 9.x (kernel 5.14+)
  - Ubuntu 24.04 (kernel 6.8+)

## Installation

### Quick Install (Manual)

```bash
# Download the binary
wget https://github.com/espegro/nfs-trail/raw/main/releases/v0.5.0/nfs-trail-v0.5.0-linux-amd64

# Verify checksum
wget https://github.com/espegro/nfs-trail/raw/main/releases/v0.5.0/nfs-trail-v0.5.0-linux-amd64.sha256
sha256sum -c nfs-trail-v0.5.0-linux-amd64.sha256

# Make executable
chmod +x nfs-trail-v0.5.0-linux-amd64

# Move to system path
sudo mv nfs-trail-v0.5.0-linux-amd64 /usr/local/bin/nfs-trail

# Verify installation
nfs-trail -version
```

### Full Install (with systemd service)

```bash
# Download binary and installer
wget https://github.com/espegro/nfs-trail/raw/main/releases/v0.5.0/nfs-trail-v0.5.0-linux-amd64
wget https://github.com/espegro/nfs-trail/raw/main/releases/v0.5.0/nfs-trail-v0.5.0-linux-amd64.sha256
wget https://github.com/espegro/nfs-trail/raw/main/install.sh

# Verify checksum
sha256sum -c nfs-trail-v0.5.0-linux-amd64.sha256

# Make executable
chmod +x nfs-trail-v0.5.0-linux-amd64
chmod +x install.sh

# Run installer (sets up config, systemd service, SELinux)
sudo ./install.sh -b nfs-trail-v0.5.0-linux-amd64

# Start service
sudo systemctl enable --now nfs-trail
```

## Quick Start

```bash
# Quick debug mode (no config needed)
sudo ./nfs-trail-v0.5.0-linux-amd64 -debug

# Debug specific user
sudo ./nfs-trail-v0.5.0-linux-amd64 -debug -uid 1000

# JSON output for testing
sudo ./nfs-trail-v0.5.0-linux-amd64 -no-config
```

## Checksum

```
d28cef8d4967e180df303c399818b5dc5e0eacf6e1e5d8b614d9ac9a3250d3ca  nfs-trail-v0.5.0-linux-amd64
```

## What's New in v0.5.0

### 🔒 Security Hardening
- Fixed critical path traversal vulnerability
- Added config DoS protection (1MB limit)
- Implemented NSS lookup timeout (2 seconds)
- Fixed log injection vulnerability

### ✨ Features
- Standalone debug mode (`-debug`)
- Human-readable output (`-simple`)
- UID filtering (`-uid`)
- Failed operations tracking
- 15 operation types monitored

See [CHANGELOG.md](../../CHANGELOG.md) for complete details.

## Requirements

- Linux kernel 5.8+ with BTF enabled (`/sys/kernel/btf/vmlinux` exists)
- Root privileges or `CAP_BPF` + `CAP_PERFMON` capabilities
- Active NFS mounts (NFSv3 or NFSv4)

## Support

- Documentation: [README.md](../../README.md)
- Security: [SECURITY_AUDIT.md](../../SECURITY_AUDIT.md)
- Issues: https://github.com/espegro/nfs-trail/issues

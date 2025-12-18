#!/bin/bash
#
# nfs-trail installation script
# Supports RHEL 9+ and Ubuntu 24.04+
#

set -e

BINARY_NAME="nfs-trail"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nfs-trail"
LOG_DIR="/var/log/nfs-trail"
SYSTEMD_DIR="/etc/systemd/system"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Detect OS
detect_os() {
    if [[ -f /etc/redhat-release ]]; then
        OS="rhel"
        VERSION=$(rpm -E %{rhel})
        log_info "Detected RHEL/CentOS $VERSION"
    elif [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" == "ubuntu" ]]; then
            OS="ubuntu"
            VERSION="$VERSION_ID"
            log_info "Detected Ubuntu $VERSION"
        else
            OS="unknown"
            log_warn "Unknown distribution: $ID"
        fi
    else
        OS="unknown"
        log_warn "Could not detect OS"
    fi
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check kernel version
    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
    KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

    if [[ $KERNEL_MAJOR -lt 5 ]] || [[ $KERNEL_MAJOR -eq 5 && $KERNEL_MINOR -lt 8 ]]; then
        log_error "Kernel 5.8+ required. Current: $(uname -r)"
        exit 1
    fi
    log_info "Kernel version OK: $(uname -r)"

    # Check BTF support
    if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
        log_error "BTF not available. Kernel must be compiled with CONFIG_DEBUG_INFO_BTF=y"
        exit 1
    fi
    log_info "BTF support OK"

    # Check if binary exists
    if [[ ! -f "$BINARY_NAME" ]]; then
        log_error "Binary '$BINARY_NAME' not found. Run 'make' first."
        exit 1
    fi
    log_info "Binary found"
}

# Install binary
install_binary() {
    log_info "Installing binary to $INSTALL_DIR..."
    install -m 0755 "$BINARY_NAME" "$INSTALL_DIR/"
}

# Install configuration
install_config() {
    log_info "Setting up configuration directory..."
    mkdir -p "$CONFIG_DIR"

    if [[ -f "$CONFIG_DIR/nfs-trail.yaml" ]]; then
        log_warn "Configuration file exists, not overwriting"
    else
        if [[ -f "configs/nfs-trail.yaml.example" ]]; then
            install -m 0644 configs/nfs-trail.yaml.example "$CONFIG_DIR/nfs-trail.yaml"
            log_info "Installed default configuration"
        else
            log_warn "Example config not found, skipping"
        fi
    fi
}

# Create log directory
create_log_dir() {
    log_info "Creating log directory..."
    mkdir -p "$LOG_DIR"
    chmod 0755 "$LOG_DIR"
}

# Install systemd service
install_systemd() {
    log_info "Installing systemd service..."

    cat > "$SYSTEMD_DIR/nfs-trail.service" << 'EOF'
[Unit]
Description=NFS File Access Logging Daemon
Documentation=https://github.com/espen/nfs-trail
After=network.target remote-fs.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nfs-trail -config /etc/nfs-trail/nfs-trail.yaml
Restart=on-failure
RestartSec=5s

# Capabilities
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/nfs-trail

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nfs-trail

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "Systemd service installed"
}

# Configure SELinux (RHEL only)
configure_selinux() {
    if [[ "$OS" != "rhel" ]]; then
        return
    fi

    # Check if SELinux is enabled
    if ! command -v getenforce &> /dev/null; then
        return
    fi

    SELINUX_STATUS=$(getenforce 2>/dev/null || echo "Disabled")
    if [[ "$SELINUX_STATUS" == "Disabled" ]]; then
        log_info "SELinux is disabled, skipping policy configuration"
        return
    fi

    log_info "Configuring SELinux policy..."

    # Create temporary directory for policy
    POLICY_DIR=$(mktemp -d)
    cd "$POLICY_DIR"

    # Create type enforcement file
    cat > nfs_trail.te << 'SELINUX_TE'
module nfs_trail 1.0;

require {
    type unconfined_service_t;
    type kernel_t;
    type sysfs_t;
    type proc_t;
    type debugfs_t;
    type nfs_t;
    type var_log_t;
    class bpf { map_create map_read map_write prog_load prog_run };
    class perf_event { open read write };
    class file { read write open getattr map execute };
    class dir { read search getattr open };
    class capability { sys_admin net_admin sys_resource dac_read_search };
    class capability2 { bpf perfmon };
}

# Allow BPF operations
allow unconfined_service_t self:bpf { map_create map_read map_write prog_load prog_run };
allow unconfined_service_t self:perf_event { open read write };
allow unconfined_service_t self:capability { sys_admin net_admin sys_resource dac_read_search };
allow unconfined_service_t self:capability2 { bpf perfmon };

# Allow reading kernel BTF
allow unconfined_service_t sysfs_t:file { read open getattr map };
allow unconfined_service_t sysfs_t:dir { read search getattr open };

# Allow reading proc
allow unconfined_service_t proc_t:file { read open getattr };
allow unconfined_service_t proc_t:dir { read search getattr open };

# Allow debugfs for BPF
allow unconfined_service_t debugfs_t:file { read write open getattr };
allow unconfined_service_t debugfs_t:dir { read search getattr open };

# Allow NFS access
allow unconfined_service_t nfs_t:file { read getattr };
allow unconfined_service_t nfs_t:dir { read search getattr };

# Allow writing logs
allow unconfined_service_t var_log_t:file { create write append open getattr };
allow unconfined_service_t var_log_t:dir { write add_name };
SELINUX_TE

    # Compile and install policy
    if command -v checkmodule &> /dev/null; then
        checkmodule -M -m -o nfs_trail.mod nfs_trail.te 2>/dev/null || true
        if [[ -f nfs_trail.mod ]]; then
            semodule_package -o nfs_trail.pp -m nfs_trail.mod 2>/dev/null || true
            if [[ -f nfs_trail.pp ]]; then
                semodule -i nfs_trail.pp 2>/dev/null || log_warn "Could not install SELinux policy"
                log_info "SELinux policy installed"
            fi
        fi
    else
        log_warn "SELinux policy tools not found, skipping"
    fi

    # Set file contexts
    if command -v semanage &> /dev/null; then
        semanage fcontext -a -t bin_t "$INSTALL_DIR/nfs-trail" 2>/dev/null || true
        restorecon -v "$INSTALL_DIR/nfs-trail" 2>/dev/null || true
    fi

    # Enable boolean for mmap
    if command -v setsebool &> /dev/null; then
        setsebool -P domain_can_mmap_files 1 2>/dev/null || true
    fi

    cd - > /dev/null
    rm -rf "$POLICY_DIR"
}

# Print completion message
print_complete() {
    echo ""
    log_info "Installation complete!"
    echo ""
    echo "To start nfs-trail:"
    echo "  sudo systemctl start nfs-trail"
    echo "  sudo systemctl enable nfs-trail"
    echo ""
    echo "To check status:"
    echo "  sudo systemctl status nfs-trail"
    echo ""
    echo "Configuration file:"
    echo "  $CONFIG_DIR/nfs-trail.yaml"
    echo ""
    echo "Log file (if file output configured):"
    echo "  $LOG_DIR/events.json"
    echo ""
}

# Main
main() {
    echo "nfs-trail installer"
    echo "==================="
    echo ""

    detect_os
    check_prerequisites
    install_binary
    install_config
    create_log_dir
    install_systemd
    configure_selinux
    print_complete
}

main "$@"

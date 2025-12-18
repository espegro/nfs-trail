# Makefile for nfs-trail

BINARY_NAME=nfs-trail
GO_CMD=go
CLANG=clang
BPFTOOL=bpftool
STRIP=llvm-strip

# Architecture detection
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    GOARCH := amd64
    BPF_ARCH := x86
else ifeq ($(ARCH),aarch64)
    GOARCH := arm64
    BPF_ARCH := arm64
endif

# Directories
INTERNAL_EBPF := internal/ebpf
BPF_DIR := $(INTERNAL_EBPF)/bpf
BPF_HEADERS := $(BPF_DIR)/headers

# Compiler flags for eBPF
BPF_CFLAGS := -O2 -g -Wall -Werror -D__TARGET_ARCH_$(BPF_ARCH)

.PHONY: all build ebpf vmlinux clean install test help

all: vmlinux ebpf build

help:
	@echo "NFS Trail - Build targets:"
	@echo "  make all        - Generate vmlinux.h, compile eBPF, build Go binary"
	@echo "  make vmlinux    - Generate vmlinux.h from BTF"
	@echo "  make ebpf       - Compile eBPF programs and generate Go bindings"
	@echo "  make build      - Build Go binary"
	@echo "  make test       - Run tests"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make install    - Install to /usr/local/bin and setup systemd service"

# Generate vmlinux.h from BTF
vmlinux:
	@echo "==> Generating vmlinux.h from BTF..."
	@mkdir -p $(BPF_HEADERS)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_HEADERS)/vmlinux.h
	@echo "==> vmlinux.h generated successfully"

# Generate eBPF bytecode and Go bindings using bpf2go
ebpf: vmlinux
	@echo "==> Compiling eBPF programs..."
	$(GO_CMD) generate ./$(INTERNAL_EBPF)/...
	@echo "==> eBPF programs compiled successfully"

# Build Go binary
build: ebpf
	@echo "==> Building $(BINARY_NAME)..."
	CGO_ENABLED=0 GOARCH=$(GOARCH) $(GO_CMD) build -o $(BINARY_NAME) ./cmd/nfs-trail
	@echo "==> Build complete: $(BINARY_NAME)"

# Run tests
test:
	@echo "==> Running tests..."
	$(GO_CMD) test -v ./...

# Install to system
install: build
	@echo "==> Installing $(BINARY_NAME)..."
	install -m 0755 $(BINARY_NAME) /usr/local/bin/
	@echo "==> Installing systemd service..."
	install -m 0644 configs/nfs-trail.service /etc/systemd/system/
	@echo "==> Installing configuration..."
	mkdir -p /etc/nfs-trail
	[ ! -f /etc/nfs-trail/nfs-trail.yaml ] && install -m 0644 configs/nfs-trail.yaml.example /etc/nfs-trail/nfs-trail.yaml || true
	@echo "==> Creating log directory..."
	mkdir -p /var/log/nfs-trail
	@echo "==> Reloading systemd..."
	systemctl daemon-reload
	@echo "==> Installation complete"
	@echo ""
	@echo "To start nfs-trail:"
	@echo "  sudo systemctl start nfs-trail"
	@echo "  sudo systemctl enable nfs-trail"

# Clean build artifacts
clean:
	@echo "==> Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -f $(BPF_DIR)/*.o
	rm -f $(INTERNAL_EBPF)/*_bpfe*.go
	rm -f $(INTERNAL_EBPF)/*_bpfe*.o
	@echo "==> Clean complete"

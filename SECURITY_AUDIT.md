# NFS Trail - Security Audit Report

**Audit Date**: 2025-12-19
**Auditor Role**: Critical Security Review
**Severity Levels**: 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low | ℹ️ Info

---

## Executive Summary

NFS Trail is a privileged daemon (root/CAP_BPF) that monitors NFS operations using eBPF. Overall code quality is **GOOD** with defensive programming patterns, but several security concerns require attention.

**Risk Level**: 🟡 MEDIUM (acceptable for internal/admin tools, needs hardening for production)

---

## 🔴 CRITICAL ISSUES

### None Found

No critical vulnerabilities that allow immediate privilege escalation or code execution.

---

## 🟠 HIGH SEVERITY ISSUES

### H1. Path Traversal in Log Output Directory Creation

**File**: `internal/output/file.go:34-36`

```go
dir := filepath.Dir(cfg.Path)
if err := os.MkdirAll(dir, 0755); err != nil {
    return nil, fmt.Errorf("creating log directory %s: %w", dir, err)
}
```

**Issue**: User-controlled config path can create arbitrary directories with mode 0755.

**Attack Scenario**:
```yaml
# Malicious config
output:
  file:
    path: /etc/cron.d/../../../../../../tmp/owned/backdoor
```

**Impact**:
- Directory traversal outside intended paths
- Can create world-writable directories in sensitive locations
- Running as root amplifies impact

**Recommendation**:
```go
// Validate path is within allowed directories
allowedPrefixes := []string{"/var/log/nfs-trail/", "/tmp/nfs-trail/"}
isAllowed := false
absPath, err := filepath.Abs(cfg.Path)
if err != nil {
    return nil, fmt.Errorf("invalid path: %w", err)
}
for _, prefix := range allowedPrefixes {
    if strings.HasPrefix(absPath, prefix) {
        isAllowed = true
        break
    }
}
if !isAllowed {
    return nil, fmt.Errorf("path %s not in allowed directories", absPath)
}
```

---

### H2. Unbounded YAML Unmarshaling

**File**: `internal/config/config.go:166`

```go
if err := yaml.Unmarshal(data, cfg); err != nil {
```

**Issue**: No size limit on YAML file, potential DoS via deeply nested structures or billion laughs attack.

**Attack Scenario**:
```yaml
# 1GB YAML with nested maps
a: &anchor
  b: &anchor2
    c: *anchor
# ... repeat 1 million times
```

**Impact**:
- Memory exhaustion
- CPU DoS via recursive parsing
- Daemon crash/unavailability

**Recommendation**:
```go
const maxConfigSize = 1 * 1024 * 1024 // 1MB

data, err := os.ReadFile(path)
if err != nil {
    return nil, fmt.Errorf("reading config file: %w", err)
}

if len(data) > maxConfigSize {
    return nil, fmt.Errorf("config file too large: %d bytes (max %d)", len(data), maxConfigSize)
}
```

---

### H3. NSS Lookup DoS

**File**: `internal/enrichment/cache.go:58,97`

```go
u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10))
```

**Issue**: Synchronous NSS lookups can block on LDAP/NIS/network failures.

**Attack Scenario**:
1. Attacker creates files as UID 999999 (not in cache)
2. NSS backend (LDAP) is slow/unresponsive
3. Lookup blocks event processing goroutine
4. System grinds to halt as events queue up

**Impact**:
- Event processing stalls
- Memory exhaustion from buffered events
- Daemon becomes unresponsive

**Recommendation**:
```go
// Add timeout to lookups
func (c *UserGroupCache) GetUsername(uid uint32) string {
    // ... cache check ...

    // Lookup with timeout
    resultChan := make(chan string, 1)
    go func() {
        u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
        if err != nil {
            resultChan <- fmt.Sprintf("uid:%d", uid)
            return
        }
        resultChan <- u.Username
    }()

    select {
    case name := <-resultChan:
        // Cache and return
    case <-time.After(2 * time.Second):
        fallback := fmt.Sprintf("uid:%d", uid)
        // Cache fallback
        return fallback
    }
}
```

---

## 🟡 MEDIUM SEVERITY ISSUES

### M1. eBPF Buffer Overflow Risk (Fixed Length Buffers)

**File**: `internal/ebpf/bpf/nfs_monitor.c:52`

```c
char filename[256];
```

**Issue**: Filename truncation to 256 bytes without checking for overflow exploitation.

**Impact**:
- Filename truncation can hide malicious activity
- Example: `legit_file.txt` + 200 bytes of padding + `; rm -rf /` gets truncated to `legit_file.txt...`

**Current Mitigation**: eBPF verifier prevents actual buffer overflows.

**Recommendation**: Log when truncation occurs:
```c
// In userspace after reading event
if (strlen(event->filename) == 255) {
    logger.Warn("Filename truncated for inode %d (possible evasion)", event->inode)
}
```

---

### M2. No Config File Integrity Check

**File**: `internal/config/config.go:159-170`

**Issue**: Config file can be modified by any process with write access, no signature/checksum verification.

**Attack Scenario**:
1. Attacker gains write to `/etc/nfs-trail/nfs-trail.yaml`
2. Modifies config to exclude their UID or log to `/dev/null`
3. Performs malicious NFS operations undetected

**Recommendation**:
```bash
# In systemd service
[Service]
ReadOnlyPaths=/etc/nfs-trail
ProtectSystem=strict
```

Or implement config signing:
```go
// Check SHA256 signature file
configHash := sha256.Sum256(data)
sigPath := path + ".sha256"
expectedHash, err := os.ReadFile(sigPath)
// Compare hashes
```

---

### M3. Race Condition in Mount Detection

**File**: `internal/mounts/detector.go:26-72`

**Issue**: TOCTOU between reading `/proc/mounts` and `unix.Stat()` call.

**Attack Scenario**:
1. NFS mount exists at scan time (line 26)
2. Mount is unmounted before `unix.Stat()` (line 50)
3. Attacker creates symlink at same mountpoint → `/etc/shadow`
4. `Stat()` follows symlink, leaks sensitive file info

**Current Mitigation**: Error is caught and mount skipped (line 51-52).

**Recommendation**: Use `lstat` instead of `stat`:
```go
if err := unix.Lstat(mountpoint, &statbuf); err != nil {
    continue
}
// Verify S_IFMT is S_IFDIR
if statbuf.Mode & unix.S_IFMT != unix.S_IFDIR {
    continue // Not a directory
}
```

---

### M4. Log Injection via Filenames

**File**: All output loggers (file.go, stdout.go, simple.go)

**Issue**: Filenames from eBPF are logged without sanitization. Newlines/control chars can break log parsing.

**Attack Scenario**:
```bash
# Create file with newline in name
touch "/mnt/nfs/fake.txt\n{\"@timestamp\":\"2025-12-19\",\"event\":{\"action\":\"nfs-file-delete\"},\"file\":{\"path\":\"/etc/shadow\"}}"
```

**Result**: Fake log entry injected, SIEM/log parser fooled.

**Recommendation**:
```go
// In LogEvent
func sanitizeFilename(s string) string {
    // Replace newlines, tabs, control chars
    s = strings.ReplaceAll(s, "\n", "\\n")
    s = strings.ReplaceAll(s, "\r", "\\r")
    s = strings.ReplaceAll(s, "\t", "\\t")
    // Remove other control chars
    return strings.Map(func(r rune) rune {
        if r < 32 || r == 127 {
            return -1 // Drop control chars
        }
        return r
    }, s)
}
```

---

## 🟢 LOW SEVERITY ISSUES

### L1. No Rate Limiting on eBPF Events

**Issue**: While userspace has rate limiting config, eBPF side sends unlimited events.

**Impact**: Memory exhaustion if attacker does massive I/O burst before userspace can drop events.

**Current Mitigation**: Ring buffer is 256KB, provides some buffering.

**Recommendation**: Add per-CPU rate limiting in eBPF:
```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64); // timestamp of last event
} rate_limit SEC(".maps");

// In kprobe
u32 key = 0;
u64 *last = bpf_map_lookup_elem(&rate_limit, &key);
u64 now = bpf_ktime_get_ns();
if (last && now - *last < 1000000) { // 1ms min interval
    return 0; // Drop
}
```

---

### L2. Prometheus Metrics Port Not Authenticated

**File**: `internal/metrics/server.go` (assumed from README)

**Issue**: `/metrics` endpoint has no authentication, anyone on network can scrape metrics.

**Impact**:
- Information disclosure (mount points, UIDs, operation counts)
- Reconnaissance for attackers

**Recommendation**:
```go
// Add basic auth or firewall rules
iptables -A INPUT -p tcp --dport 9090 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 9090 -j DROP
```

---

### L3. Potential Integer Overflow in Bytes Counting

**File**: `internal/metrics/metrics.go:111-113`

```go
if operation == "read" && bytes > 0 {
    BytesRead.Add(float64(bytes))
```

**Issue**: `int64` to `float64` conversion loses precision for very large files (>2^53 bytes).

**Impact**: Metrics inaccuracy for files >9 PB (unlikely in practice).

**Recommendation**: Use Prometheus native int64 counters if available, or document limitation.

---

## ℹ️ INFORMATIONAL / BEST PRACTICES

### I1. No Audit Logging of Config Changes

**Recommendation**: Log when config is loaded/changed:
```go
logger.Info("Configuration loaded from %s (sha256: %x)", path, sha256.Sum256(data))
```

---

### I2. No Capability Dropping

**Issue**: Daemon runs with full root/CAP_BPF throughout lifetime.

**Recommendation**: Drop unnecessary capabilities after eBPF load:
```go
// After AttachProbes()
unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
// Drop CAP_SYS_ADMIN if not needed
```

---

### I3. No Seccomp Filter

**Recommendation**: Add seccomp-bpf to restrict syscalls:
```go
import "github.com/seccomp/libseccomp-golang"

// Allow only: read, write, epoll_wait, etc.
// Deny: execve, ptrace, etc.
```

---

### I4. Hardcoded Paths

**File**: Multiple

**Issue**: Paths like `/proc/mounts`, `/etc/nfs-trail/` are hardcoded.

**Recommendation**: Make configurable for testing/containers:
```go
const (
    ProcMounts = getEnv("NFS_TRAIL_PROC_MOUNTS", "/proc/mounts")
    ConfigDir  = getEnv("NFS_TRAIL_CONFIG_DIR", "/etc/nfs-trail")
)
```

---

## Positive Security Observations ✅

1. **Safe Go Practices**:
   - Uses `filepath.Join` correctly (no manual path concatenation)
   - Mutexes protect shared state
   - Proper error handling

2. **eBPF Verifier**: Prevents memory safety issues in kernel code

3. **BPF CO-RE**: Reduces attack surface vs. kernel module

4. **Defensive Config**: Default UID filtering excludes root (UID 0)

5. **No Unsafe Code**: No `unsafe` package usage in critical paths

6. **Dependencies**: Minimal external deps, all from trusted sources

---

## Remediation Priority

### Immediate (Before Production):
1. ✅ Add config file size limit (H2)
2. ✅ Add NSS lookup timeout (H3)
3. ✅ Validate output paths (H1)
4. ✅ Sanitize filenames in logs (M4)

### Short-term (Next Release):
1. Add TOCTOU mitigation in mount detection (M3)
2. Add config integrity checking (M2)
3. Implement filename truncation logging (M1)
4. Add metrics endpoint auth (L2)

### Long-term (Hardening):
1. Seccomp filtering (I3)
2. Capability dropping (I2)
3. eBPF-side rate limiting (L1)

---

## Conclusion

**Overall Assessment**: Code is well-written with good defensive patterns. Main risks are:
- Path traversal in logging config
- DoS via NSS lookups or large configs
- Log injection via filenames

**Suitable for**: Internal admin tools, controlled environments
**NOT suitable for**: Internet-facing services, untrusted users

**Recommendation**: Implement H1-H3 fixes before production deployment.

---

**End of Security Audit**

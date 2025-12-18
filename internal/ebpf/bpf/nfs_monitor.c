//go:build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "nfs_monitor.h"

// x86_64 register access for kprobe parameters
// First parameter is in RDI register
#define KPROBE_PARM1(regs) ((regs)->di)

// x86_64 register access for kretprobe return value
// Return value is in RAX register
#define PT_REGS_RC(regs) ((regs)->ax)

char LICENSE[] SEC("license") = "GPL";

// eBPF Maps

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB
} events SEC(".maps");

// Map of NFS mount device IDs to monitor
// Key: device_id (from stat.st_dev), Value: 1 if should monitor
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u8);
} nfs_mounts SEC(".maps");

// Note: UID filtering is done in userspace to support large ranges
// This map is kept for future use if needed for small exclude lists
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} uid_filter SEC(".maps");

// Entry context for read/write operations (to correlate with return value)
struct file_io_context {
    __u64 timestamp_ns;
    __u64 inode;
    __u64 device_id;
    __u32 uid;
    __u32 gid;
    char comm[16];
    char filename[256];
};

// Temporary storage for correlating entry/exit probes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);  // pid_tgid
    __type(value, struct file_io_context);
} pending_reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);  // pid_tgid
    __type(value, struct file_io_context);
} pending_writes SEC(".maps");

// Helper function to check if we should trace this event
static __always_inline bool should_trace_event(struct file *file) {
    // Note: UID filtering is done in userspace

    if (!file)
        return false;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return false;

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb)
        return false;

    // Get device ID
    dev_t dev = BPF_CORE_READ(sb, s_dev);
    __u64 dev_id = dev;

    // Check if this is an NFS mount we care about
    __u8 *is_nfs = bpf_map_lookup_elem(&nfs_mounts, &dev_id);
    if (!is_nfs || *is_nfs == 0) {
        return false;
    }

    return true;
}

// Maximum path depth to walk (eBPF loop limit)
#define MAX_PATH_DEPTH 20

// Helper to get full path from dentry by walking up the tree
// Builds path in reverse, then we store it reversed (caller handles display)
static __always_inline int get_dentry_path(struct dentry *dentry, char *buf, int size) {
    if (!dentry || !buf || size <= 0)
        return -1;

    // Temporary buffer for path components
    char component[64];
    int pos = size - 1;
    buf[pos] = '\0';

    struct dentry *current = dentry;
    struct dentry *parent;

    #pragma unroll
    for (int i = 0; i < MAX_PATH_DEPTH; i++) {
        if (!current)
            break;

        parent = BPF_CORE_READ(current, d_parent);

        // Stop if we've reached the root (parent == self)
        if (parent == current)
            break;

        // Get component name
        const unsigned char *name_ptr = BPF_CORE_READ(current, d_name.name);
        if (!name_ptr)
            break;

        int len = bpf_probe_read_kernel_str(component, sizeof(component), name_ptr);
        if (len <= 1)  // Empty or just null terminator
            break;

        len--;  // Remove null terminator from length

        // Check if we have space (need len + 1 for slash)
        if (pos - len - 1 < 0)
            break;

        // Prepend component
        pos -= len;
        bpf_probe_read_kernel(buf + pos, len, component);

        // Prepend slash
        pos--;
        buf[pos] = '/';

        current = parent;
    }

    // If we didn't add anything, just get the basename
    if (pos == size - 1) {
        const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
        if (name_ptr) {
            bpf_probe_read_kernel_str(buf, size, name_ptr);
        } else {
            buf[0] = '\0';
        }
        return 0;
    }

    // Move path to beginning of buffer
    int path_len = size - 1 - pos;
    for (int i = 0; i < path_len && i < size - 1; i++) {
        buf[i] = buf[pos + i];
    }
    buf[path_len] = '\0';

    return path_len;
}


// vfs_read kprobe entry
SEC("kprobe/vfs_read")
int trace_vfs_read_entry(struct pt_regs *ctx) {
    // Get function arguments
    // vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
    struct file *file = (struct file *)KPROBE_PARM1(ctx);

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Check if we should trace this event (device ID filtering only)
    if (!should_trace_event(file)) {
        return 0;
    }

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u32 gid = uid_gid >> 32;

    // Store context for return probe
    struct file_io_context ctx_data = {0};
    ctx_data.timestamp_ns = bpf_ktime_get_ns();
    ctx_data.uid = uid;
    ctx_data.gid = gid;

    // Get process name
    bpf_get_current_comm(&ctx_data.comm, sizeof(ctx_data.comm));

    // Get inode and device info
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (inode) {
        ctx_data.inode = BPF_CORE_READ(inode, i_ino);
        struct super_block *sb = BPF_CORE_READ(inode, i_sb);
        if (sb) {
            ctx_data.device_id = BPF_CORE_READ(sb, s_dev);
        }
    }

    // Get filename from file's dentry
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (dentry) {
        get_dentry_path(dentry, ctx_data.filename, PATH_MAX);
    } else {
        ctx_data.filename[0] = '\0';
    }

    // Store in map for return probe
    bpf_map_update_elem(&pending_reads, &pid_tgid, &ctx_data, BPF_ANY);

    return 0;
}

// vfs_read kretprobe (to capture return value)
SEC("kretprobe/vfs_read")
int trace_vfs_read_return(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    // Look up stored context
    struct file_io_context *ctx_data = bpf_map_lookup_elem(&pending_reads, &pid_tgid);
    if (!ctx_data) {
        return 0; // No entry context, skip
    }

    // Get return value (bytes read or error code)
    long bytes = PT_REGS_RC(ctx);

    // Only log successful reads (positive byte count)
    if (bytes <= 0) {
        bpf_map_delete_elem(&pending_reads, &pid_tgid);
        return 0;
    }

    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&pending_reads, &pid_tgid);
        return 0;
    }

    // Fill event data from stored context
    event->timestamp_ns = ctx_data->timestamp_ns;
    event->pid = pid;
    event->tid = tid;
    event->uid = ctx_data->uid;
    event->gid = ctx_data->gid;
    event->operation = NFS_TRAIL_OP_READ;
    event->flags = 0;
    event->return_value = bytes;
    event->inode = ctx_data->inode;
    event->device_id = ctx_data->device_id;

    // Copy process name and filename
    __builtin_memcpy(event->comm, ctx_data->comm, sizeof(event->comm));
    __builtin_memcpy(event->filename, ctx_data->filename, sizeof(event->filename));

    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);

    // Clean up map entry
    bpf_map_delete_elem(&pending_reads, &pid_tgid);

    return 0;
}

// vfs_write kprobe entry
SEC("kprobe/vfs_write")
int trace_vfs_write_entry(struct pt_regs *ctx) {
    // Get function arguments
    // vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
    struct file *file = (struct file *)KPROBE_PARM1(ctx);

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Check if we should trace this event (device ID filtering only)
    if (!should_trace_event(file)) {
        return 0;
    }

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u32 gid = uid_gid >> 32;

    // Store context for return probe
    struct file_io_context ctx_data = {0};
    ctx_data.timestamp_ns = bpf_ktime_get_ns();
    ctx_data.uid = uid;
    ctx_data.gid = gid;

    // Get process name
    bpf_get_current_comm(&ctx_data.comm, sizeof(ctx_data.comm));

    // Get inode and device info
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (inode) {
        ctx_data.inode = BPF_CORE_READ(inode, i_ino);
        struct super_block *sb = BPF_CORE_READ(inode, i_sb);
        if (sb) {
            ctx_data.device_id = BPF_CORE_READ(sb, s_dev);
        }
    }

    // Get filename from file's dentry
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (dentry) {
        get_dentry_path(dentry, ctx_data.filename, PATH_MAX);
    } else {
        ctx_data.filename[0] = '\0';
    }

    // Store in map for return probe
    bpf_map_update_elem(&pending_writes, &pid_tgid, &ctx_data, BPF_ANY);

    return 0;
}

// vfs_write kretprobe (to capture return value)
SEC("kretprobe/vfs_write")
int trace_vfs_write_return(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    // Look up stored context
    struct file_io_context *ctx_data = bpf_map_lookup_elem(&pending_writes, &pid_tgid);
    if (!ctx_data) {
        return 0; // No entry context, skip
    }

    // Get return value (bytes written or error code)
    long bytes = PT_REGS_RC(ctx);

    // Only log successful writes (positive byte count)
    if (bytes <= 0) {
        bpf_map_delete_elem(&pending_writes, &pid_tgid);
        return 0;
    }

    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&pending_writes, &pid_tgid);
        return 0;
    }

    // Fill event data from stored context
    event->timestamp_ns = ctx_data->timestamp_ns;
    event->pid = pid;
    event->tid = tid;
    event->uid = ctx_data->uid;
    event->gid = ctx_data->gid;
    event->operation = NFS_TRAIL_OP_WRITE;
    event->flags = 0;
    event->return_value = bytes;
    event->inode = ctx_data->inode;
    event->device_id = ctx_data->device_id;

    // Copy process name and filename
    __builtin_memcpy(event->comm, ctx_data->comm, sizeof(event->comm));
    __builtin_memcpy(event->filename, ctx_data->filename, sizeof(event->filename));

    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);

    // Clean up map entry
    bpf_map_delete_elem(&pending_writes, &pid_tgid);

    return 0;
}

// vfs_getattr kprobe (for stat/ls operations)
SEC("kprobe/vfs_getattr")
int trace_vfs_getattr_entry(struct pt_regs *ctx) {
    // vfs_getattr(const struct path *path, struct kstat *stat, ...)
    // We need to extract the path and check if it's on NFS

    struct path *path_ptr = (struct path *)KPROBE_PARM1(ctx);
    if (!path_ptr) {
        return 0;
    }

    struct path path_val;
    bpf_probe_read_kernel(&path_val, sizeof(path_val), path_ptr);

    struct dentry *dentry = path_val.dentry;
    if (!dentry) {
        return 0;
    }

    // Get inode to check device ID
    struct inode *inode;
    bpf_probe_read_kernel(&inode, sizeof(inode), &dentry->d_inode);
    if (!inode) {
        return 0;
    }

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb) {
        return 0;
    }

    dev_t dev = BPF_CORE_READ(sb, s_dev);
    __u64 dev_id = dev;

    // Check if this is an NFS mount we care about
    __u8 *is_nfs = bpf_map_lookup_elem(&nfs_mounts, &dev_id);
    if (!is_nfs || *is_nfs == 0) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u32 gid = uid_gid >> 32;

    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Fill event data
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->uid = uid;
    event->gid = gid;
    event->operation = NFS_TRAIL_OP_STAT;
    event->flags = 0;
    event->return_value = 0;

    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get inode info
    event->inode = BPF_CORE_READ(inode, i_ino);
    event->device_id = dev_id;

    // Get path from dentry
    get_dentry_path(dentry, event->filename, PATH_MAX);

    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);

    return 0;
}

// vfs_unlink kprobe (for delete/rm operations)
SEC("kprobe/vfs_unlink")
int trace_vfs_unlink_entry(struct pt_regs *ctx) {
    // vfs_unlink signature on kernel 6.x:
    // int vfs_unlink(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
    // dentry is third parameter (RDX on x86_64)
    struct dentry *dentry = (struct dentry *)((struct pt_regs *)ctx)->dx;

    if (!dentry) {
        return 0;
    }

    // Get inode from dentry
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        return 0;
    }

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb) {
        return 0;
    }

    dev_t dev = BPF_CORE_READ(sb, s_dev);
    __u64 dev_id = dev;

    // Check if this is an NFS mount we care about
    __u8 *is_nfs = bpf_map_lookup_elem(&nfs_mounts, &dev_id);
    if (!is_nfs || *is_nfs == 0) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u32 gid = uid_gid >> 32;

    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Fill event data
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->uid = uid;
    event->gid = gid;
    event->operation = NFS_TRAIL_OP_DELETE;
    event->flags = 0;
    event->return_value = 0;

    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get inode info
    event->inode = BPF_CORE_READ(inode, i_ino);
    event->device_id = dev_id;

    // Get filename
    get_dentry_path(dentry, event->filename, PATH_MAX);

    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);

    return 0;
}

// vfs_rename kprobe (for file/directory rename operations)
SEC("kprobe/vfs_rename")
int trace_vfs_rename_entry(struct pt_regs *ctx) {
    // vfs_rename signature on kernel 6.x:
    // int vfs_rename(struct renamedata *rd)
    // struct renamedata layout:
    //   0: struct mnt_idmap *rd_mnt_idmap (8 bytes)
    //   8: struct inode *rd_old_dir (8 bytes)
    //  16: struct dentry *rd_old_dentry (8 bytes) <- we want this
    //  24: struct inode *rd_new_dir (8 bytes)
    //  32: struct dentry *rd_new_dentry (8 bytes)

    // On x86_64, first parameter is in RDI
    void *renamedata = (void *)KPROBE_PARM1(ctx);
    if (!renamedata) {
        return 0;
    }

    struct dentry *old_dentry;
    bpf_probe_read_kernel(&old_dentry, sizeof(old_dentry), renamedata + 16);

    if (!old_dentry) {
        return 0;
    }

    // Get inode to check device ID
    struct inode *inode = BPF_CORE_READ(old_dentry, d_inode);
    if (!inode) {
        return 0;
    }

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb) {
        return 0;
    }

    dev_t dev = BPF_CORE_READ(sb, s_dev);
    __u64 dev_id = dev;

    // Check if this is an NFS mount we care about
    __u8 *is_nfs = bpf_map_lookup_elem(&nfs_mounts, &dev_id);
    if (!is_nfs || *is_nfs == 0) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u32 gid = uid_gid >> 32;

    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Fill event data
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->uid = uid;
    event->gid = gid;
    event->operation = NFS_TRAIL_OP_RENAME;
    event->flags = 0;
    event->return_value = 0;

    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get inode info
    event->inode = BPF_CORE_READ(inode, i_ino);
    event->device_id = dev_id;

    // Get old filename path
    get_dentry_path(old_dentry, event->filename, PATH_MAX);

    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);

    return 0;
}

// vfs_mkdir kprobe (for directory creation)
SEC("kprobe/vfs_mkdir")
int trace_vfs_mkdir_entry(struct pt_regs *ctx) {
    // vfs_mkdir signature on kernel 6.x:
    // int vfs_mkdir(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, umode_t mode)
    // We need to skip idmap and get dentry from third parameter
    // On x86_64: RDI, RSI, RDX, RCX, R8, R9
    // So dentry is in RDX
    struct dentry *dentry = (struct dentry *)((struct pt_regs *)ctx)->dx;

    if (!dentry) {
        return 0;
    }

    // Get parent directory inode to check device ID
    struct inode *dir = BPF_CORE_READ(dentry, d_parent, d_inode);
    if (!dir) {
        return 0;
    }

    struct super_block *sb = BPF_CORE_READ(dir, i_sb);
    if (!sb) {
        return 0;
    }

    dev_t dev = BPF_CORE_READ(sb, s_dev);
    __u64 dev_id = dev;

    // Check if this is an NFS mount we care about
    __u8 *is_nfs = bpf_map_lookup_elem(&nfs_mounts, &dev_id);
    if (!is_nfs || *is_nfs == 0) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u32 gid = uid_gid >> 32;

    // Get mode from fourth parameter (RCX on x86_64)
    __u32 mode = (__u32)((struct pt_regs *)ctx)->cx;

    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Fill event data
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->uid = uid;
    event->gid = gid;
    event->operation = NFS_TRAIL_OP_MKDIR;
    event->flags = mode;
    event->return_value = 0;

    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get inode info from parent
    event->inode = BPF_CORE_READ(dir, i_ino);
    event->device_id = dev_id;

    // Get directory name
    get_dentry_path(dentry, event->filename, PATH_MAX);

    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);

    return 0;
}

// vfs_rmdir kprobe (for directory removal)
SEC("kprobe/vfs_rmdir")
int trace_vfs_rmdir_entry(struct pt_regs *ctx) {
    // vfs_rmdir signature on kernel 6.x:
    // int vfs_rmdir(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry)
    // dentry is third parameter (RDX on x86_64)
    struct dentry *dentry = (struct dentry *)((struct pt_regs *)ctx)->dx;

    if (!dentry) {
        return 0;
    }

    // Get inode from dentry
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        return 0;
    }

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb) {
        return 0;
    }

    dev_t dev = BPF_CORE_READ(sb, s_dev);
    __u64 dev_id = dev;

    // Check if this is an NFS mount we care about
    __u8 *is_nfs = bpf_map_lookup_elem(&nfs_mounts, &dev_id);
    if (!is_nfs || *is_nfs == 0) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u32 gid = uid_gid >> 32;

    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Fill event data
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->uid = uid;
    event->gid = gid;
    event->operation = NFS_TRAIL_OP_RMDIR;
    event->flags = 0;
    event->return_value = 0;

    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get inode info
    event->inode = BPF_CORE_READ(inode, i_ino);
    event->device_id = dev_id;

    // Get directory name
    get_dentry_path(dentry, event->filename, PATH_MAX);

    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);

    return 0;
}

// notify_change kprobe (for chmod/chown operations)
SEC("kprobe/notify_change")
int trace_vfs_setattr_entry(struct pt_regs *ctx) {
    // notify_change signature on kernel 6.x:
    // int notify_change(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr, struct inode **delegated_inode)
    // dentry is second parameter (RSI on x86_64)
    struct dentry *dentry = (struct dentry *)((struct pt_regs *)ctx)->si;

    if (!dentry) {
        return 0;
    }

    // Get inode from dentry
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        return 0;
    }

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb) {
        return 0;
    }

    dev_t dev = BPF_CORE_READ(sb, s_dev);
    __u64 dev_id = dev;

    // Check if this is an NFS mount we care about
    __u8 *is_nfs = bpf_map_lookup_elem(&nfs_mounts, &dev_id);
    if (!is_nfs || *is_nfs == 0) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u32 gid = uid_gid >> 32;

    // Get iattr from third parameter (RDX on x86_64)
    // struct iattr has ia_valid field to determine what's being changed
    void *attr = (void *)((struct pt_regs *)ctx)->dx;
    __u32 ia_valid = 0;
    if (attr) {
        bpf_probe_read_kernel(&ia_valid, sizeof(ia_valid), attr);
    }

    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Fill event data
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->uid = uid;
    event->gid = gid;

    // Determine if it's chmod or chown based on ia_valid flags
    // ATTR_MODE = 0x1, ATTR_UID = 0x2, ATTR_GID = 0x4
    if (ia_valid & 0x1) {
        event->operation = NFS_TRAIL_OP_CHMOD;
    } else if (ia_valid & 0x6) {  // ATTR_UID or ATTR_GID
        event->operation = NFS_TRAIL_OP_CHOWN;
    } else {
        event->operation = NFS_TRAIL_OP_CHMOD;  // Default
    }

    event->flags = ia_valid;
    event->return_value = 0;

    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get inode info
    event->inode = BPF_CORE_READ(inode, i_ino);
    event->device_id = dev_id;

    // Get filename
    get_dentry_path(dentry, event->filename, PATH_MAX);

    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);

    return 0;
}

// vfs_symlink kprobe (for symbolic link creation)
SEC("kprobe/vfs_symlink")
int trace_vfs_symlink_entry(struct pt_regs *ctx) {
    // vfs_symlink signature on kernel 6.x:
    // int vfs_symlink(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, const char *oldname)
    // dentry is third parameter (RDX on x86_64)
    struct dentry *dentry = (struct dentry *)((struct pt_regs *)ctx)->dx;

    if (!dentry) {
        return 0;
    }

    // Get parent directory inode to check device ID
    struct inode *dir = BPF_CORE_READ(dentry, d_parent, d_inode);
    if (!dir) {
        return 0;
    }

    struct super_block *sb = BPF_CORE_READ(dir, i_sb);
    if (!sb) {
        return 0;
    }

    dev_t dev = BPF_CORE_READ(sb, s_dev);
    __u64 dev_id = dev;

    // Check if this is an NFS mount we care about
    __u8 *is_nfs = bpf_map_lookup_elem(&nfs_mounts, &dev_id);
    if (!is_nfs || *is_nfs == 0) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u32 gid = uid_gid >> 32;

    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Fill event data
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->uid = uid;
    event->gid = gid;
    event->operation = NFS_TRAIL_OP_SYMLINK;
    event->flags = 0;
    event->return_value = 0;

    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get inode info from parent directory
    event->inode = BPF_CORE_READ(dir, i_ino);
    event->device_id = dev_id;

    // Get symlink name
    get_dentry_path(dentry, event->filename, PATH_MAX);

    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);

    return 0;
}

// vfs_link kprobe (for hard link creation)
SEC("kprobe/vfs_link")
int trace_vfs_link_entry(struct pt_regs *ctx) {
    // vfs_link signature on kernel 6.x:
    // int vfs_link(struct dentry *old_dentry, struct mnt_idmap *idmap, struct inode *dir, struct dentry *new_dentry, ...)
    // old_dentry is first parameter (RDI on x86_64)
    struct dentry *old_dentry = (struct dentry *)KPROBE_PARM1(ctx);

    if (!old_dentry) {
        return 0;
    }

    // Get inode from old_dentry
    struct inode *inode = BPF_CORE_READ(old_dentry, d_inode);
    if (!inode) {
        return 0;
    }

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb) {
        return 0;
    }

    dev_t dev = BPF_CORE_READ(sb, s_dev);
    __u64 dev_id = dev;

    // Check if this is an NFS mount we care about
    __u8 *is_nfs = bpf_map_lookup_elem(&nfs_mounts, &dev_id);
    if (!is_nfs || *is_nfs == 0) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u32 gid = uid_gid >> 32;

    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Fill event data
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->uid = uid;
    event->gid = gid;
    event->operation = NFS_TRAIL_OP_LINK;
    event->flags = 0;
    event->return_value = 0;

    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get inode info
    event->inode = BPF_CORE_READ(inode, i_ino);
    event->device_id = dev_id;

    // Get filename path from old_dentry
    get_dentry_path(old_dentry, event->filename, PATH_MAX);

    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);

    return 0;
}

// vfs_setxattr kprobe (for extended attribute manipulation)
SEC("kprobe/vfs_setxattr")
int trace_vfs_setxattr_entry(struct pt_regs *ctx) {
    // vfs_setxattr signature on kernel 6.x:
    // int vfs_setxattr(struct mnt_idmap *idmap, struct dentry *dentry, const char *name, const void *value, size_t size, int flags)
    // dentry is second parameter (RSI on x86_64)
    struct dentry *dentry = (struct dentry *)((struct pt_regs *)ctx)->si;

    if (!dentry) {
        return 0;
    }

    // Get inode from dentry
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        return 0;
    }

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb) {
        return 0;
    }

    dev_t dev = BPF_CORE_READ(sb, s_dev);
    __u64 dev_id = dev;

    // Check if this is an NFS mount we care about
    __u8 *is_nfs = bpf_map_lookup_elem(&nfs_mounts, &dev_id);
    if (!is_nfs || *is_nfs == 0) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u32 gid = uid_gid >> 32;

    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Fill event data
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->uid = uid;
    event->gid = gid;
    event->operation = NFS_TRAIL_OP_SETXATTR;
    event->flags = 0;
    event->return_value = 0;

    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get inode info
    event->inode = BPF_CORE_READ(inode, i_ino);
    event->device_id = dev_id;

    // Get filename
    get_dentry_path(dentry, event->filename, PATH_MAX);

    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);

    return 0;
}


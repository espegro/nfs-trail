#ifndef __NFS_MONITOR_H__
#define __NFS_MONITOR_H__

#define TASK_COMM_LEN 16
#define PATH_MAX 256

// Operation types (prefixed to avoid kernel enum conflicts)
enum nfs_trail_operation {
    NFS_TRAIL_OP_READ = 1,
    NFS_TRAIL_OP_WRITE = 2,
    NFS_TRAIL_OP_OPEN = 3,
    NFS_TRAIL_OP_CLOSE = 4,
    NFS_TRAIL_OP_STAT = 5,
    NFS_TRAIL_OP_CHMOD = 6,
    NFS_TRAIL_OP_CHOWN = 7,
    NFS_TRAIL_OP_RENAME = 8,
    NFS_TRAIL_OP_DELETE = 9,
    NFS_TRAIL_OP_MKDIR = 10,
    NFS_TRAIL_OP_RMDIR = 11,
    NFS_TRAIL_OP_SYMLINK = 12,
    NFS_TRAIL_OP_LINK = 13,
    NFS_TRAIL_OP_SETXATTR = 14,
    NFS_TRAIL_OP_TRUNCATE = 15,
};

// Event structure sent from kernel to userspace
struct file_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 inode;
    __u64 device_id;
    __u32 operation;
    __s64 return_value;  // bytes read/written or error code
    __u32 flags;         // open flags, chmod mode, etc.
    char comm[TASK_COMM_LEN];
    char filename[PATH_MAX];
};

#endif /* __NFS_MONITOR_H__ */

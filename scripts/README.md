# NFS Trail Helper Scripts

Utility scripts for analyzing and working with nfs-trail logs.

## analyze-logs.sh

Analyze JSON logs from nfs-trail using jq.

### Requirements

- jq (install: `sudo yum install jq` or `sudo apt-get install jq`)

### Quick Examples

```bash
# Show all failed operations
./analyze-logs.sh errors /var/log/nfs-trail/events.json

# Show permission denied operations
./analyze-logs.sh denied /var/log/nfs-trail/events.json

# Top 10 most active users
./analyze-logs.sh top-users 10 /var/log/nfs-trail/events.json

# Top 10 most accessed files
./analyze-logs.sh top-files 10 /var/log/nfs-trail/events.json

# All operations by user 'alice'
./analyze-logs.sh user alice /var/log/nfs-trail/events.json

# Bytes read/written per user
./analyze-logs.sh bytes /var/log/nfs-trail/events.json

# Overall statistics
./analyze-logs.sh stats /var/log/nfs-trail/events.json
```

### Piping from journalctl

```bash
# Analyze logs from systemd journal
sudo journalctl -u nfs-trail -o cat | ./analyze-logs.sh stats

# Show denied operations in last hour
sudo journalctl -u nfs-trail --since "1 hour ago" -o cat | ./analyze-logs.sh denied

# Follow live errors
sudo journalctl -u nfs-trail -f -o cat | ./analyze-logs.sh errors
```

### All Commands

- `errors` - Show all failed operations
- `denied` - Show permission denied (EACCES)
- `notfound` - Show file not found (ENOENT)
- `top-users [N]` - Top N most active users
- `top-files [N]` - Top N most accessed files
- `top-ops [N]` - Top N operation types
- `user <username>` - Filter by username
- `uid <uid>` - Filter by UID
- `op <operation>` - Filter by operation type
- `bytes` - Show bytes read/written per user
- `stats` - Overall statistics
- `last [N]` - Show last N events
- `follow <file>` - Follow log file (tail -f)

### Security Use Cases

**Detect suspicious activity:**
```bash
# Permission denied operations (potential scanning)
./analyze-logs.sh denied /var/log/nfs-trail/events.json

# Most active users (potential data exfiltration)
./analyze-logs.sh top-users 5 /var/log/nfs-trail/events.json

# Unusual file access patterns
./analyze-logs.sh top-files 20 /var/log/nfs-trail/events.json
```

**Data transfer monitoring:**
```bash
# Who is transferring the most data?
./analyze-logs.sh bytes /var/log/nfs-trail/events.json

# All write operations by a user
./analyze-logs.sh user alice /var/log/nfs-trail/events.json | grep write
```

**Compliance auditing:**
```bash
# All permission changes
./analyze-logs.sh op chmod /var/log/nfs-trail/events.json

# All file deletions
./analyze-logs.sh op delete /var/log/nfs-trail/events.json

# All ownership changes
./analyze-logs.sh op chown /var/log/nfs-trail/events.json
```

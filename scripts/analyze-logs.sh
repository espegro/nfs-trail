#!/bin/bash
#
# NFS Trail Log Analyzer
# Uses jq to analyze JSON logs from nfs-trail
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# Check for jq
check_jq() {
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed"
        echo ""
        echo "Install jq:"
        echo "  RHEL/CentOS: sudo yum install jq"
        echo "  Ubuntu:      sudo apt-get install jq"
        exit 1
    fi
}

# Print usage
print_usage() {
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                       NFS TRAIL LOG ANALYZER                                 ║
║  Analyze JSON logs with jq                                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

USAGE:
  analyze-logs.sh <command> [logfile]

  If logfile is omitted, reads from stdin (allows piping)

COMMANDS:

  errors              Show all failed operations
  denied              Show permission denied operations (EACCES)
  notfound            Show file not found operations (ENOENT)

  top-users [N]       Show top N most active users (default: 10)
  top-files [N]       Show top N most accessed files (default: 10)
  top-ops [N]         Show top N operation types (default: 10)

  user <username>     Show all operations by specific user
  uid <uid>           Show all operations by specific UID

  op <operation>      Show specific operation type
                      (read, write, chmod, chown, delete, etc.)

  bytes               Show total bytes read/written per user
  stats               Show overall statistics

  last [N]            Show last N events (default: 20)
  follow              Follow log file (like tail -f)

  help                Show this help

EXAMPLES:

  # Analyze log file
  ./analyze-logs.sh errors /var/log/nfs-trail/events.json

  # Pipe from journalctl
  sudo journalctl -u nfs-trail -o cat | ./analyze-logs.sh stats

  # Show denied operations in last hour
  sudo journalctl -u nfs-trail --since "1 hour ago" -o cat | ./analyze-logs.sh denied

  # Top 5 most active users
  ./analyze-logs.sh top-users 5 /var/log/nfs-trail/events.json

  # All operations by user 'alice'
  ./analyze-logs.sh user alice /var/log/nfs-trail/events.json

  # Follow live events (errors only)
  sudo journalctl -u nfs-trail -f -o cat | ./analyze-logs.sh errors

EOF
}

# Get input (file or stdin)
get_input() {
    if [[ -n "$1" ]]; then
        if [[ ! -f "$1" ]]; then
            log_error "File not found: $1"
            exit 1
        fi
        cat "$1"
    else
        cat
    fi
}

# Command: Show errors
cmd_errors() {
    get_input "$1" | jq -r '
        select(.nfs.operation.success == false) |
        "\(.["@timestamp"]) [\(.nfs.operation.error // "UNKNOWN")] \(.event.action) by \(.user.name) (\(.user.id)) - \(.file.path)"
    '
}

# Command: Show permission denied
cmd_denied() {
    get_input "$1" | jq -r '
        select(.nfs.operation.error == "EACCES") |
        "\(.["@timestamp"]) \(.event.action) by \(.user.name) (\(.user.id)) - \(.file.path)"
    '
}

# Command: Show file not found
cmd_notfound() {
    get_input "$1" | jq -r '
        select(.nfs.operation.error == "ENOENT") |
        "\(.["@timestamp"]) \(.event.action) by \(.user.name) (\(.user.id)) - \(.file.path)"
    '
}

# Command: Top users
cmd_top_users() {
    local limit=${1:-10}
    local logfile=$2

    echo -e "${BLUE}Top $limit Most Active Users:${NC}"
    echo "────────────────────────────────────────"

    get_input "$logfile" | jq -r '.user.name' | \
        sort | uniq -c | sort -rn | head -n "$limit" | \
        awk '{printf "  %6d  %s\n", $1, $2}'
}

# Command: Top files
cmd_top_files() {
    local limit=${1:-10}
    local logfile=$2

    echo -e "${BLUE}Top $limit Most Accessed Files:${NC}"
    echo "────────────────────────────────────────"

    get_input "$logfile" | jq -r '.file.path' | \
        sort | uniq -c | sort -rn | head -n "$limit" | \
        awk '{printf "  %6d  %s\n", $1, $2}'
}

# Command: Top operations
cmd_top_ops() {
    local limit=${1:-10}
    local logfile=$2

    echo -e "${BLUE}Top $limit Operation Types:${NC}"
    echo "────────────────────────────────────────"

    get_input "$logfile" | jq -r '.nfs.operation.type' | \
        sort | uniq -c | sort -rn | head -n "$limit" | \
        awk '{printf "  %6d  %s\n", $1, $2}'
}

# Command: Filter by user
cmd_user() {
    local username=$1
    local logfile=$2

    if [[ -z "$username" ]]; then
        log_error "Username required"
        echo "Usage: analyze-logs.sh user <username> [logfile]"
        exit 1
    fi

    get_input "$logfile" | jq -r --arg user "$username" '
        select(.user.name == $user) |
        "\(.["@timestamp"]) \(.nfs.operation.type) \(.file.path) [\(.nfs.operation.bytes // 0) bytes]"
    '
}

# Command: Filter by UID
cmd_uid() {
    local uid=$1
    local logfile=$2

    if [[ -z "$uid" ]]; then
        log_error "UID required"
        echo "Usage: analyze-logs.sh uid <uid> [logfile]"
        exit 1
    fi

    get_input "$logfile" | jq -r --arg uid "$uid" '
        select(.user.id == $uid) |
        "\(.["@timestamp"]) \(.nfs.operation.type) \(.file.path) [\(.nfs.operation.bytes // 0) bytes]"
    '
}

# Command: Filter by operation
cmd_op() {
    local operation=$1
    local logfile=$2

    if [[ -z "$operation" ]]; then
        log_error "Operation type required"
        echo "Usage: analyze-logs.sh op <operation> [logfile]"
        echo "Available: read, write, open, close, stat, chmod, chown, rename, delete, mkdir, rmdir, symlink, link, setxattr, truncate"
        exit 1
    fi

    get_input "$logfile" | jq -r --arg op "$operation" '
        select(.nfs.operation.type == $op) |
        "\(.["@timestamp"]) by \(.user.name) - \(.file.path) [\(.nfs.operation.bytes // 0) bytes]"
    '
}

# Command: Bytes statistics
cmd_bytes() {
    local logfile=$1

    echo -e "${BLUE}Bytes Read/Written by User:${NC}"
    echo "────────────────────────────────────────"

    get_input "$logfile" | jq -r '
        select(.nfs.operation.bytes > 0) |
        "\(.user.name) \(.nfs.operation.type) \(.nfs.operation.bytes)"
    ' | awk '
        {
            user = $1
            op = $2
            bytes = $3

            if (op == "read") {
                read[user] += bytes
            } else if (op == "write") {
                write[user] += bytes
            }
            total[user] += bytes
        }
        END {
            for (user in total) {
                printf "  %-20s  Read: %12s  Write: %12s  Total: %12s\n",
                    user,
                    format_bytes(read[user]),
                    format_bytes(write[user]),
                    format_bytes(total[user])
            }
        }

        function format_bytes(bytes) {
            if (bytes >= 1073741824) return sprintf("%.2f GB", bytes/1073741824)
            if (bytes >= 1048576) return sprintf("%.2f MB", bytes/1048576)
            if (bytes >= 1024) return sprintf("%.2f KB", bytes/1024)
            return sprintf("%d B", bytes)
        }
    ' | sort -k6 -rh
}

# Command: Overall statistics
cmd_stats() {
    local logfile=$1

    echo -e "${BLUE}Overall Statistics:${NC}"
    echo "════════════════════════════════════════"

    local stats=$(get_input "$logfile" | jq -s '
        {
            total_events: length,
            unique_users: ([.[].user.name] | unique | length),
            unique_files: ([.[].file.path] | unique | length),
            failed_ops: ([.[] | select(.nfs.operation.success == false)] | length),
            operations: (group_by(.nfs.operation.type) | map({(.[0].nfs.operation.type): length}) | add),
            total_bytes_read: ([.[] | select(.nfs.operation.type == "read") | .nfs.operation.bytes // 0] | add),
            total_bytes_written: ([.[] | select(.nfs.operation.type == "write") | .nfs.operation.bytes // 0] | add)
        }
    ')

    echo "$stats" | jq -r '
        "  Total Events:        \(.total_events)",
        "  Unique Users:        \(.unique_users)",
        "  Unique Files:        \(.unique_files)",
        "  Failed Operations:   \(.failed_ops)",
        "",
        "  Total Bytes Read:    \(.total_bytes_read) bytes",
        "  Total Bytes Written: \(.total_bytes_written) bytes",
        "",
        "  Operations by Type:"
    '

    echo "$stats" | jq -r '.operations | to_entries[] | "    \(.key): \(.value)"' | sort -t: -k2 -rn
}

# Command: Last N events
cmd_last() {
    local limit=${1:-20}
    local logfile=$2

    get_input "$logfile" | tail -n "$limit" | jq -r '
        "\(.["@timestamp"]) [\(.nfs.operation.type)] \(.user.name) -> \(.file.path)"
    '
}

# Command: Follow log
cmd_follow() {
    local logfile=$1

    if [[ -z "$logfile" ]]; then
        log_error "Log file required for follow mode"
        echo "Usage: analyze-logs.sh follow /var/log/nfs-trail/events.json"
        exit 1
    fi

    tail -f "$logfile" | jq -r --unbuffered '
        "\(.["@timestamp"]) [\(.nfs.operation.type)] \(.user.name) -> \(.file.path) [\(.nfs.operation.bytes // 0) bytes]"
    '
}

# Main
main() {
    check_jq

    if [[ $# -lt 1 ]]; then
        print_usage
        exit 0
    fi

    local command=$1
    shift

    case "$command" in
        errors)
            cmd_errors "$@"
            ;;
        denied)
            cmd_denied "$@"
            ;;
        notfound)
            cmd_notfound "$@"
            ;;
        top-users)
            cmd_top_users "$@"
            ;;
        top-files)
            cmd_top_files "$@"
            ;;
        top-ops)
            cmd_top_ops "$@"
            ;;
        user)
            cmd_user "$@"
            ;;
        uid)
            cmd_uid "$@"
            ;;
        op)
            cmd_op "$@"
            ;;
        bytes)
            cmd_bytes "$@"
            ;;
        stats)
            cmd_stats "$@"
            ;;
        last)
            cmd_last "$@"
            ;;
        follow)
            cmd_follow "$@"
            ;;
        help|--help|-h)
            print_usage
            ;;
        *)
            log_error "Unknown command: $command"
            echo ""
            print_usage
            exit 1
            ;;
    esac
}

main "$@"

package enrichment

import (
    "fmt"
    "os/user"
    "strconv"
    "sync"
    "time"

    lru "github.com/hashicorp/golang-lru/v2"
    "github.com/espegro/nfs-trail/internal/metrics"
)

const (
    // LookupTimeout prevents blocking on slow NSS backends (LDAP/NIS)
    LookupTimeout = 2 * time.Second
)

// UserGroupCache caches username and groupname lookups with LRU eviction
type UserGroupCache struct {
    userCache  *lru.Cache[uint32, *cacheEntry]
    groupCache *lru.Cache[uint32, *cacheEntry]
    ttl        time.Duration
    mu         sync.RWMutex
}

type cacheEntry struct {
    name      string
    timestamp time.Time
}

// NewUserGroupCache creates a new user/group cache with LRU size limit
func NewUserGroupCache(ttl time.Duration, size int) *UserGroupCache {
    if size <= 0 {
        size = 10000 // Default fallback
    }
    // Create LRU caches with configurable size limit
    userCache, _ := lru.New[uint32, *cacheEntry](size)
    groupCache, _ := lru.New[uint32, *cacheEntry](size)

    return &UserGroupCache{
        userCache:  userCache,
        groupCache: groupCache,
        ttl:        ttl,
    }
}

// GetUsername returns the username for a given UID
func (c *UserGroupCache) GetUsername(uid uint32) string {
    // Check cache first
    c.mu.RLock()
    if entry, ok := c.userCache.Get(uid); ok {
        if time.Since(entry.timestamp) < c.ttl {
            c.mu.RUnlock()
            metrics.RecordCacheHit()
            return entry.name
        }
    }
    c.mu.RUnlock()

    // Cache miss - lookup from system with timeout
    metrics.RecordCacheMiss()

    // Security: Use timeout to prevent blocking on slow NSS backends
    resultChan := make(chan string, 1)
    go func() {
        u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
        if err != nil {
            resultChan <- fmt.Sprintf("uid:%d", uid)
        } else {
            resultChan <- u.Username
        }
    }()

    var name string
    select {
    case name = <-resultChan:
        // Lookup succeeded within timeout
    case <-time.After(LookupTimeout):
        // Timeout - use fallback
        name = fmt.Sprintf("uid:%d", uid)
    }

    // Cache the result (whether success or timeout fallback)
    c.mu.Lock()
    c.userCache.Add(uid, &cacheEntry{
        name:      name,
        timestamp: time.Now(),
    })
    c.mu.Unlock()

    return name
}

// GetGroupname returns the group name for a given GID
func (c *UserGroupCache) GetGroupname(gid uint32) string {
    // Check cache first
    c.mu.RLock()
    if entry, ok := c.groupCache.Get(gid); ok {
        if time.Since(entry.timestamp) < c.ttl {
            c.mu.RUnlock()
            metrics.RecordCacheHit()
            return entry.name
        }
    }
    c.mu.RUnlock()

    // Cache miss - lookup from system with timeout
    metrics.RecordCacheMiss()

    // Security: Use timeout to prevent blocking on slow NSS backends
    resultChan := make(chan string, 1)
    go func() {
        g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10))
        if err != nil {
            resultChan <- fmt.Sprintf("gid:%d", gid)
        } else {
            resultChan <- g.Name
        }
    }()

    var name string
    select {
    case name = <-resultChan:
        // Lookup succeeded within timeout
    case <-time.After(LookupTimeout):
        // Timeout - use fallback
        name = fmt.Sprintf("gid:%d", gid)
    }

    // Cache the result (whether success or timeout fallback)
    c.mu.Lock()
    c.groupCache.Add(gid, &cacheEntry{
        name:      name,
        timestamp: time.Now(),
    })
    c.mu.Unlock()

    return name
}

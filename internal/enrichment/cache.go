package enrichment

import (
    "fmt"
    "os/user"
    "strconv"
    "sync"
    "time"

    lru "github.com/hashicorp/golang-lru/v2"
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
            return entry.name
        }
    }
    c.mu.RUnlock()

    // Lookup from system
    u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
    if err != nil {
        // Cache the failure too
        fallback := fmt.Sprintf("uid:%d", uid)
        c.mu.Lock()
        c.userCache.Add(uid, &cacheEntry{
            name:      fallback,
            timestamp: time.Now(),
        })
        c.mu.Unlock()
        return fallback
    }

    // Cache the result
    c.mu.Lock()
    c.userCache.Add(uid, &cacheEntry{
        name:      u.Username,
        timestamp: time.Now(),
    })
    c.mu.Unlock()

    return u.Username
}

// GetGroupname returns the group name for a given GID
func (c *UserGroupCache) GetGroupname(gid uint32) string {
    // Check cache first
    c.mu.RLock()
    if entry, ok := c.groupCache.Get(gid); ok {
        if time.Since(entry.timestamp) < c.ttl {
            c.mu.RUnlock()
            return entry.name
        }
    }
    c.mu.RUnlock()

    // Lookup from system
    g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10))
    if err != nil {
        // Cache the failure too
        fallback := fmt.Sprintf("gid:%d", gid)
        c.mu.Lock()
        c.groupCache.Add(gid, &cacheEntry{
            name:      fallback,
            timestamp: time.Now(),
        })
        c.mu.Unlock()
        return fallback
    }

    // Cache the result
    c.mu.Lock()
    c.groupCache.Add(gid, &cacheEntry{
        name:      g.Name,
        timestamp: time.Now(),
    })
    c.mu.Unlock()

    return g.Name
}

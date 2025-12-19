package ratelimit

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// EventLimiter handles rate limiting and drop tracking for events
type EventLimiter struct {
	maxEventsPerSec      int
	dropPolicy           string
	logDroppedEvents     bool
	dropStatsIntervalSec int

	// Metrics
	eventsReceived  uint64
	eventsProcessed uint64
	eventsDropped   uint64
	lastDropTime    time.Time
	dropMu          sync.Mutex

	// Rate limiting
	tokens         int
	maxTokens      int
	lastRefillTime time.Time
	tokenMu        sync.Mutex
}

// NewEventLimiter creates a new event limiter
func NewEventLimiter(maxEventsPerSec int, dropPolicy string, logDroppedEvents bool, dropStatsIntervalSec int) *EventLimiter {
	limiter := &EventLimiter{
		maxEventsPerSec:      maxEventsPerSec,
		dropPolicy:           dropPolicy,
		logDroppedEvents:     logDroppedEvents,
		dropStatsIntervalSec: dropStatsIntervalSec,
		maxTokens:            maxEventsPerSec,
		tokens:               maxEventsPerSec,
		lastRefillTime:       time.Now(),
	}

	// Start stats reporter if enabled
	if dropStatsIntervalSec > 0 {
		go limiter.statsReporter()
	}

	return limiter
}

// AllowEvent checks if an event should be allowed or dropped
// Returns true if event should be processed
func (l *EventLimiter) AllowEvent() bool {
	atomic.AddUint64(&l.eventsReceived, 1)

	// If no rate limit, always allow
	if l.maxEventsPerSec == 0 {
		atomic.AddUint64(&l.eventsProcessed, 1)
		return true
	}

	// Check token bucket
	l.tokenMu.Lock()
	defer l.tokenMu.Unlock()

	// Refill tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(l.lastRefillTime)
	if elapsed >= time.Second {
		tokensToAdd := int(elapsed.Seconds()) * l.maxEventsPerSec
		l.tokens = min(l.tokens+tokensToAdd, l.maxTokens)
		l.lastRefillTime = now
	}

	// Check if we have tokens
	if l.tokens > 0 {
		l.tokens--
		atomic.AddUint64(&l.eventsProcessed, 1)
		return true
	}

	// No tokens - drop event
	l.recordDrop()
	return false
}

// recordDrop records a dropped event
func (l *EventLimiter) recordDrop() {
	atomic.AddUint64(&l.eventsDropped, 1)

	if l.logDroppedEvents {
		l.dropMu.Lock()
		defer l.dropMu.Unlock()

		now := time.Now()
		// Log first drop or if more than 5 seconds since last drop log
		if l.lastDropTime.IsZero() || now.Sub(l.lastDropTime) > 5*time.Second {
			log.Printf("WARNING: Event dropped (rate limit exceeded). Total drops: %d",
				atomic.LoadUint64(&l.eventsDropped))
			l.lastDropTime = now
		}
	}
}

// GetStats returns current statistics
func (l *EventLimiter) GetStats() (received, processed, dropped uint64) {
	return atomic.LoadUint64(&l.eventsReceived),
		atomic.LoadUint64(&l.eventsProcessed),
		atomic.LoadUint64(&l.eventsDropped)
}

// statsReporter periodically logs drop statistics
func (l *EventLimiter) statsReporter() {
	ticker := time.NewTicker(time.Duration(l.dropStatsIntervalSec) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		received, processed, dropped := l.GetStats()
		if dropped > 0 {
			dropRate := float64(dropped) / float64(received) * 100
			log.Printf("Event stats: received=%d processed=%d dropped=%d (%.2f%%)",
				received, processed, dropped, dropRate)
		}
	}
}

// ResetStats resets all statistics counters
func (l *EventLimiter) ResetStats() {
	atomic.StoreUint64(&l.eventsReceived, 0)
	atomic.StoreUint64(&l.eventsProcessed, 0)
	atomic.StoreUint64(&l.eventsDropped, 0)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

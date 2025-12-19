package ratelimit

import (
	"sync/atomic"

	"github.com/espegro/nfs-trail/internal/logger"
)

// BufferedSender handles non-blocking sends to a channel with drop policy
type BufferedSender struct {
	channel      chan interface{}
	dropPolicy   string
	logDrops     bool
	droppedCount uint64
}

// NewBufferedSender creates a new buffered sender
func NewBufferedSender(channel chan interface{}, dropPolicy string, logDrops bool) *BufferedSender {
	return &BufferedSender{
		channel:    channel,
		dropPolicy: dropPolicy,
		logDrops:   logDrops,
	}
}

// Send attempts to send data to the channel
// Returns true if sent, false if dropped
func (b *BufferedSender) Send(data interface{}) bool {
	select {
	case b.channel <- data:
		// Successfully sent
		return true
	default:
		// Channel is full - drop based on policy
		return b.handleFullChannel(data)
	}
}

// handleFullChannel handles a full channel based on drop policy
func (b *BufferedSender) handleFullChannel(newData interface{}) bool {
	dropped := atomic.AddUint64(&b.droppedCount, 1)

	if b.logDrops {
		// Log every 100th drop to avoid log spam
		if dropped%100 == 1 {
			logger.Warn("Event channel full, dropping events (total dropped: %d, policy: %s)",
				dropped, b.dropPolicy)
		}
	}

	switch b.dropPolicy {
	case "newest":
		// Drop the new event
		return false

	case "oldest":
		// Try to drop oldest event and add new one
		select {
		case <-b.channel:
			// Successfully removed oldest, now try to add new
			select {
			case b.channel <- newData:
				return true
			default:
				// Still full (race condition), drop new anyway
				return false
			}
		default:
			// Channel became empty (race condition), try to send again
			select {
			case b.channel <- newData:
				return true
			default:
				return false
			}
		}

	default:
		// Unknown policy, drop newest
		return false
	}
}

// GetDroppedCount returns the number of dropped events
func (b *BufferedSender) GetDroppedCount() uint64 {
	return atomic.LoadUint64(&b.droppedCount)
}

// ResetDroppedCount resets the dropped events counter
func (b *BufferedSender) ResetDroppedCount() {
	atomic.StoreUint64(&b.droppedCount, 0)
}

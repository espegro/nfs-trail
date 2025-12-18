package aggregator

import (
	"fmt"
	"sync"
	"time"

	"github.com/espen/nfs-trail/internal/types"
)

// EventAggregator buffers and aggregates similar events
type EventAggregator struct {
	windowDuration time.Duration
	minEventCount  int
	maxFileList    int
	buffer         map[string]*AggregatedEvent
	mu             sync.Mutex
	outputChan     chan<- interface{} // Can send either *types.FileEvent or *AggregatedEvent
}

// AggregatedEvent represents multiple similar events grouped together
type AggregatedEvent struct {
	FirstEvent    *types.FileEvent
	LastEvent     *types.FileEvent
	Count         int
	Files         []string // List of unique filenames
	StartTime     time.Time
	EndTime       time.Time
	timer         *time.Timer
}

// NewEventAggregator creates a new event aggregator
func NewEventAggregator(windowMS int, minEventCount int, maxFileList int, outputChan chan<- interface{}) *EventAggregator {
	return &EventAggregator{
		windowDuration: time.Duration(windowMS) * time.Millisecond,
		minEventCount:  minEventCount,
		maxFileList:    maxFileList,
		buffer:         make(map[string]*AggregatedEvent),
		outputChan:     outputChan,
	}
}

// ProcessEvent processes an incoming event
func (a *EventAggregator) ProcessEvent(event *types.FileEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Create key for aggregation: PID + Operation + MountPoint
	key := a.getAggregationKey(event)

	agg, exists := a.buffer[key]
	if !exists {
		// Create new aggregated event
		agg = &AggregatedEvent{
			FirstEvent: event,
			LastEvent:  event,
			Count:      1,
			Files:      []string{event.Filename},
			StartTime:  event.Timestamp,
			EndTime:    event.Timestamp,
		}
		a.buffer[key] = agg

		// Set timer to flush this aggregation
		agg.timer = time.AfterFunc(a.windowDuration, func() {
			a.flushKey(key)
		})
	} else {
		// Update existing aggregation
		agg.LastEvent = event
		agg.Count++
		agg.EndTime = event.Timestamp

		// Add filename if not already in list and under limit
		if len(agg.Files) < a.maxFileList {
			// Check if filename already in list
			found := false
			for _, f := range agg.Files {
				if f == event.Filename {
					found = true
					break
				}
			}
			if !found {
				agg.Files = append(agg.Files, event.Filename)
			}
		}

		// Reset timer
		agg.timer.Stop()
		agg.timer = time.AfterFunc(a.windowDuration, func() {
			a.flushKey(key)
		})
	}
}

// getAggregationKey creates a key for grouping events
func (a *EventAggregator) getAggregationKey(event *types.FileEvent) string {
	// Group by: PID + UID + Operation + MountPoint
	// This groups sequential operations from same process/user on same mount
	return fmt.Sprintf("%d:%d:%s:%s", event.PID, event.UID, event.Operation.String(), event.MountPoint)
}

// flushKey flushes a specific aggregation key
func (a *EventAggregator) flushKey(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	agg, exists := a.buffer[key]
	if !exists {
		return
	}

	// Remove from buffer
	delete(a.buffer, key)

	// Decide whether to send aggregated or individual event
	if agg.Count >= a.minEventCount {
		// Send aggregated event
		a.outputChan <- agg
	} else {
		// Send individual events (count was too low to aggregate)
		// For simplicity, just send the first event
		a.outputChan <- agg.FirstEvent
	}
}

// Flush flushes all pending aggregations
func (a *EventAggregator) Flush() {
	a.mu.Lock()
	keys := make([]string, 0, len(a.buffer))
	for k := range a.buffer {
		keys = append(keys, k)
	}
	a.mu.Unlock()

	for _, key := range keys {
		a.flushKey(key)
	}
}

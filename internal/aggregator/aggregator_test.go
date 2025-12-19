package aggregator

import (
	"testing"
	"time"

	"github.com/espen/nfs-trail/internal/types"
)

func TestNewEventAggregator(t *testing.T) {
	outputChan := make(chan interface{}, 10)
	defer close(outputChan)

	agg := NewEventAggregator(500, 3, 10, outputChan)

	if agg == nil {
		t.Fatal("NewEventAggregator returned nil")
	}

	if agg.windowDuration != 500*time.Millisecond {
		t.Errorf("Expected windowDuration 500ms, got %v", agg.windowDuration)
	}

	if agg.minEventCount != 3 {
		t.Errorf("Expected minEventCount 3, got %d", agg.minEventCount)
	}

	if agg.maxFileList != 10 {
		t.Errorf("Expected maxFileList 10, got %d", agg.maxFileList)
	}
}

func TestGetAggregationKey(t *testing.T) {
	outputChan := make(chan interface{}, 10)
	defer close(outputChan)

	agg := NewEventAggregator(500, 3, 10, outputChan)

	event1 := &types.FileEvent{
		PID:        1234,
		UID:        1000,
		Operation:  types.OpRead,
		MountPoint: "/mnt/nfs",
	}

	event2 := &types.FileEvent{
		PID:        1234,
		UID:        1000,
		Operation:  types.OpRead,
		MountPoint: "/mnt/nfs",
	}

	event3 := &types.FileEvent{
		PID:        5678,
		UID:        1000,
		Operation:  types.OpRead,
		MountPoint: "/mnt/nfs",
	}

	key1 := agg.getAggregationKey(event1)
	key2 := agg.getAggregationKey(event2)
	key3 := agg.getAggregationKey(event3)

	if key1 != key2 {
		t.Error("Expected same key for events with same PID/UID/Op/Mount")
	}

	if key1 == key3 {
		t.Error("Expected different key for events with different PID")
	}
}

func TestProcessEvent_SingleEvent(t *testing.T) {
	outputChan := make(chan interface{}, 10)
	defer close(outputChan)

	agg := NewEventAggregator(100, 3, 10, outputChan)

	event := &types.FileEvent{
		PID:        1234,
		UID:        1000,
		Operation:  types.OpRead,
		MountPoint: "/mnt/nfs",
		Filename:   "test.txt",
		Timestamp:  time.Now(),
	}

	agg.ProcessEvent(event)

	// Check that event is buffered
	agg.mu.Lock()
	if len(agg.buffer) != 1 {
		t.Errorf("Expected 1 buffered aggregation, got %d", len(agg.buffer))
	}
	agg.mu.Unlock()

	// Wait for timer to flush
	time.Sleep(150 * time.Millisecond)

	// Check that event was flushed to output
	select {
	case output := <-outputChan:
		switch v := output.(type) {
		case *types.FileEvent:
			if v.Filename != "test.txt" {
				t.Errorf("Expected filename 'test.txt', got '%s'", v.Filename)
			}
		case *AggregatedEvent:
			t.Error("Expected single FileEvent, got AggregatedEvent")
		default:
			t.Errorf("Unexpected output type: %T", output)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Timeout waiting for output")
	}
}

func TestProcessEvent_MultipleEvents_Aggregated(t *testing.T) {
	outputChan := make(chan interface{}, 10)
	defer close(outputChan)

	agg := NewEventAggregator(100, 3, 10, outputChan)

	// Send 5 events with same key
	for i := 0; i < 5; i++ {
		event := &types.FileEvent{
			PID:        1234,
			UID:        1000,
			Operation:  types.OpRead,
			MountPoint: "/mnt/nfs",
			Filename:   "test.txt",
			Timestamp:  time.Now(),
		}
		agg.ProcessEvent(event)
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for aggregation to flush
	time.Sleep(150 * time.Millisecond)

	// Check that aggregated event was sent
	select {
	case output := <-outputChan:
		switch v := output.(type) {
		case *AggregatedEvent:
			if v.Count != 5 {
				t.Errorf("Expected count 5, got %d", v.Count)
			}
			if len(v.Files) != 1 {
				t.Errorf("Expected 1 unique file, got %d", len(v.Files))
			}
		case *types.FileEvent:
			t.Error("Expected AggregatedEvent, got FileEvent")
		default:
			t.Errorf("Unexpected output type: %T", output)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Timeout waiting for aggregated output")
	}
}

func TestProcessEvent_FileListLimit(t *testing.T) {
	outputChan := make(chan interface{}, 10)
	defer close(outputChan)

	agg := NewEventAggregator(100, 2, 3, outputChan) // maxFileList = 3

	// Send 5 events with different filenames
	for i := 0; i < 5; i++ {
		event := &types.FileEvent{
			PID:        1234,
			UID:        1000,
			Operation:  types.OpRead,
			MountPoint: "/mnt/nfs",
			Filename:   time.Now().Format("file-15:04:05.000.txt"),
			Timestamp:  time.Now(),
		}
		agg.ProcessEvent(event)
		time.Sleep(5 * time.Millisecond)
	}

	// Wait for aggregation to flush
	time.Sleep(150 * time.Millisecond)

	// Check that file list is limited to 3
	select {
	case output := <-outputChan:
		switch v := output.(type) {
		case *AggregatedEvent:
			if v.Count != 5 {
				t.Errorf("Expected count 5, got %d", v.Count)
			}
			if len(v.Files) > 3 {
				t.Errorf("Expected max 3 files in list, got %d", len(v.Files))
			}
		default:
			t.Errorf("Expected AggregatedEvent, got %T", output)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Timeout waiting for output")
	}
}

func TestProcessEvent_BelowMinEventCount(t *testing.T) {
	outputChan := make(chan interface{}, 10)
	defer close(outputChan)

	agg := NewEventAggregator(100, 5, 10, outputChan) // minEventCount = 5

	// Send only 2 events
	for i := 0; i < 2; i++ {
		event := &types.FileEvent{
			PID:        1234,
			UID:        1000,
			Operation:  types.OpRead,
			MountPoint: "/mnt/nfs",
			Filename:   "test.txt",
			Timestamp:  time.Now(),
		}
		agg.ProcessEvent(event)
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for flush
	time.Sleep(150 * time.Millisecond)

	// Should receive a single event (below min count, sends FirstEvent only)
	select {
	case output := <-outputChan:
		switch output.(type) {
		case *types.FileEvent:
			// Expected: single representative event
		case *AggregatedEvent:
			t.Error("Did not expect AggregatedEvent for count below minimum")
		default:
			t.Errorf("Unexpected output type: %T", output)
		}
	case <-time.After(50 * time.Millisecond):
		t.Error("Timeout waiting for output")
	}
}

func TestProcessEvent_DifferentKeys(t *testing.T) {
	outputChan := make(chan interface{}, 10)
	defer close(outputChan)

	agg := NewEventAggregator(100, 2, 10, outputChan)

	// Send events with different PIDs (different keys)
	event1 := &types.FileEvent{
		PID:        1234,
		UID:        1000,
		Operation:  types.OpRead,
		MountPoint: "/mnt/nfs",
		Filename:   "test1.txt",
		Timestamp:  time.Now(),
	}

	event2 := &types.FileEvent{
		PID:        5678,
		UID:        1000,
		Operation:  types.OpRead,
		MountPoint: "/mnt/nfs",
		Filename:   "test2.txt",
		Timestamp:  time.Now(),
	}

	agg.ProcessEvent(event1)
	agg.ProcessEvent(event2)

	// Should have 2 separate aggregations
	agg.mu.Lock()
	bufferSize := len(agg.buffer)
	agg.mu.Unlock()

	if bufferSize != 2 {
		t.Errorf("Expected 2 buffered aggregations, got %d", bufferSize)
	}
}

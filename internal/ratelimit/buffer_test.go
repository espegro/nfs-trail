package ratelimit

import (
	"testing"
	"time"
)

func TestNewBufferedSender(t *testing.T) {
	ch := make(chan interface{}, 10)
	sender := NewBufferedSender(ch, "oldest", false)

	if sender == nil {
		t.Fatal("NewBufferedSender returned nil")
	}

	if sender.dropPolicy != "oldest" {
		t.Errorf("Expected dropPolicy 'oldest', got '%s'", sender.dropPolicy)
	}
}

func TestSend_Success(t *testing.T) {
	ch := make(chan interface{}, 10)
	sender := NewBufferedSender(ch, "oldest", false)

	// Send to empty channel - should succeed
	if !sender.Send("test") {
		t.Error("Expected successful send to empty channel")
	}

	// Verify data arrived
	select {
	case data := <-ch:
		if data != "test" {
			t.Errorf("Expected 'test', got %v", data)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout waiting for data")
	}

	// Should have 0 drops
	if sender.GetDroppedCount() != 0 {
		t.Errorf("Expected 0 drops, got %d", sender.GetDroppedCount())
	}
}

func TestSend_DropNewest(t *testing.T) {
	ch := make(chan interface{}, 2)
	sender := NewBufferedSender(ch, "newest", false)

	// Fill the channel
	sender.Send("event1")
	sender.Send("event2")

	// Next send should fail (drop newest)
	if sender.Send("event3") {
		t.Error("Expected send to fail when channel is full (drop newest)")
	}

	// Verify dropped count
	if sender.GetDroppedCount() != 1 {
		t.Errorf("Expected 1 drop, got %d", sender.GetDroppedCount())
	}

	// Verify original events are still in channel
	data1 := <-ch
	data2 := <-ch

	if data1 != "event1" || data2 != "event2" {
		t.Errorf("Expected event1 and event2, got %v and %v", data1, data2)
	}
}

func TestSend_DropOldest(t *testing.T) {
	ch := make(chan interface{}, 2)
	sender := NewBufferedSender(ch, "oldest", false)

	// Fill the channel
	sender.Send("event1")
	sender.Send("event2")

	// Next send should succeed by dropping oldest
	if !sender.Send("event3") {
		t.Error("Expected send to succeed (drop oldest)")
	}

	// Verify dropped count
	if sender.GetDroppedCount() != 1 {
		t.Errorf("Expected 1 drop, got %d", sender.GetDroppedCount())
	}

	// Verify event1 was dropped, event2 and event3 remain
	data1 := <-ch
	data2 := <-ch

	// Should get event2 and event3 (event1 was dropped)
	if data1 != "event2" || data2 != "event3" {
		t.Errorf("Expected event2 and event3, got %v and %v", data1, data2)
	}
}

func TestSend_MultipleDrops(t *testing.T) {
	ch := make(chan interface{}, 2)
	sender := NewBufferedSender(ch, "newest", false)

	// Fill the channel
	sender.Send("event1")
	sender.Send("event2")

	// Try to send 5 more - all should be dropped
	for i := 3; i <= 7; i++ {
		sender.Send("event" + string(rune('0'+i)))
	}

	// Should have 5 drops
	if sender.GetDroppedCount() != 5 {
		t.Errorf("Expected 5 drops, got %d", sender.GetDroppedCount())
	}

	// Original events should still be there
	data1 := <-ch
	data2 := <-ch

	if data1 != "event1" || data2 != "event2" {
		t.Errorf("Expected event1 and event2, got %v and %v", data1, data2)
	}
}

func TestResetDroppedCount(t *testing.T) {
	ch := make(chan interface{}, 1)
	sender := NewBufferedSender(ch, "newest", false)

	// Fill channel and cause drops
	sender.Send("event1")
	sender.Send("event2") // dropped
	sender.Send("event3") // dropped

	if sender.GetDroppedCount() != 2 {
		t.Errorf("Expected 2 drops, got %d", sender.GetDroppedCount())
	}

	// Reset
	sender.ResetDroppedCount()

	if sender.GetDroppedCount() != 0 {
		t.Errorf("Expected 0 drops after reset, got %d", sender.GetDroppedCount())
	}
}

func TestSend_Concurrent(t *testing.T) {
	ch := make(chan interface{}, 100)
	sender := NewBufferedSender(ch, "oldest", false)

	// Send events concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 20; j++ {
				sender.Send(id*100 + j)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Drain channel
	count := 0
	timeout := time.After(100 * time.Millisecond)
loop:
	for {
		select {
		case <-ch:
			count++
		case <-timeout:
			break loop
		}
	}

	dropped := int(sender.GetDroppedCount())

	// With concurrent sends to a small buffer, we expect some drops
	// Just verify that we didn't lose everything
	if count == 0 {
		t.Error("Expected some events to be received")
	}

	// Verify that count + dropped is reasonable (within buffer size + some margin)
	// Due to race conditions, exact count is not guaranteed
	if count > 100 {
		t.Errorf("Received more events (%d) than buffer size (100)", count)
	}

	t.Logf("Concurrent test: received=%d, dropped=%d", count, dropped)
}

func TestSend_UnknownDropPolicy(t *testing.T) {
	ch := make(chan interface{}, 1)
	sender := NewBufferedSender(ch, "invalid_policy", false)

	// Fill channel
	sender.Send("event1")

	// Should default to dropping newest
	if sender.Send("event2") {
		t.Error("Expected send to fail with unknown drop policy (should default to drop newest)")
	}

	// Verify event1 is still there
	data := <-ch
	if data != "event1" {
		t.Errorf("Expected event1, got %v", data)
	}
}

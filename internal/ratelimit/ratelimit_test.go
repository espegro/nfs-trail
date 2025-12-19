package ratelimit

import (
	"testing"
	"time"
)

func TestNewEventLimiter(t *testing.T) {
	limiter := NewEventLimiter(1000, "oldest", true, 0)

	if limiter == nil {
		t.Fatal("NewEventLimiter returned nil")
	}

	if limiter.maxEventsPerSec != 1000 {
		t.Errorf("Expected maxEventsPerSec 1000, got %d", limiter.maxEventsPerSec)
	}

	if limiter.dropPolicy != "oldest" {
		t.Errorf("Expected dropPolicy 'oldest', got '%s'", limiter.dropPolicy)
	}
}

func TestAllowEvent_Unlimited(t *testing.T) {
	limiter := NewEventLimiter(0, "oldest", false, 0) // 0 = unlimited

	// Should allow all events
	for i := 0; i < 10000; i++ {
		if !limiter.AllowEvent() {
			t.Errorf("Event %d was blocked with unlimited rate", i)
		}
	}

	received, processed, dropped := limiter.GetStats()
	if received != 10000 {
		t.Errorf("Expected 10000 received, got %d", received)
	}
	if processed != 10000 {
		t.Errorf("Expected 10000 processed, got %d", processed)
	}
	if dropped != 0 {
		t.Errorf("Expected 0 dropped, got %d", dropped)
	}
}

func TestAllowEvent_RateLimit(t *testing.T) {
	limiter := NewEventLimiter(100, "oldest", false, 0) // 100 events/sec

	// Send 100 events quickly - should all pass (initial tokens)
	allowed := 0
	for i := 0; i < 100; i++ {
		if limiter.AllowEvent() {
			allowed++
		}
	}

	if allowed != 100 {
		t.Errorf("Expected 100 events allowed, got %d", allowed)
	}

	// Send 50 more immediately - should be blocked
	blocked := 0
	for i := 0; i < 50; i++ {
		if !limiter.AllowEvent() {
			blocked++
		}
	}

	if blocked == 0 {
		t.Error("Expected some events to be blocked after exhausting tokens")
	}

	received, processed, dropped := limiter.GetStats()
	if dropped == 0 {
		t.Error("Expected some events to be dropped")
	}
	if received != processed+dropped {
		t.Errorf("Stats mismatch: received=%d, processed=%d, dropped=%d", received, processed, dropped)
	}
}

func TestAllowEvent_TokenRefill(t *testing.T) {
	limiter := NewEventLimiter(10, "oldest", false, 0) // 10 events/sec

	// Exhaust initial tokens
	for i := 0; i < 10; i++ {
		limiter.AllowEvent()
	}

	// Next event should be blocked
	if limiter.AllowEvent() {
		t.Error("Expected event to be blocked after exhausting tokens")
	}

	// Wait for refill (just over 1 second)
	time.Sleep(1100 * time.Millisecond)

	// Should have ~10 new tokens
	allowed := 0
	for i := 0; i < 10; i++ {
		if limiter.AllowEvent() {
			allowed++
		}
	}

	if allowed < 8 { // Allow some margin for timing
		t.Errorf("Expected ~10 events allowed after refill, got %d", allowed)
	}
}

func TestGetStats(t *testing.T) {
	limiter := NewEventLimiter(5, "oldest", false, 0)

	// Send 10 events (5 should pass, 5 should drop)
	for i := 0; i < 10; i++ {
		limiter.AllowEvent()
	}

	received, processed, dropped := limiter.GetStats()

	if received != 10 {
		t.Errorf("Expected 10 received, got %d", received)
	}

	if processed != 5 {
		t.Errorf("Expected 5 processed, got %d", processed)
	}

	if dropped != 5 {
		t.Errorf("Expected 5 dropped, got %d", dropped)
	}
}

func TestResetStats(t *testing.T) {
	limiter := NewEventLimiter(10, "oldest", false, 0)

	// Generate some stats
	for i := 0; i < 20; i++ {
		limiter.AllowEvent()
	}

	// Verify stats exist
	received, _, dropped := limiter.GetStats()
	if received == 0 || dropped == 0 {
		t.Fatal("Expected non-zero stats before reset")
	}

	// Reset
	limiter.ResetStats()

	// Verify stats are cleared
	received, processed, dropped := limiter.GetStats()
	if received != 0 || processed != 0 || dropped != 0 {
		t.Errorf("Expected all stats to be 0 after reset, got received=%d processed=%d dropped=%d",
			received, processed, dropped)
	}
}

func TestAllowEvent_Concurrent(t *testing.T) {
	limiter := NewEventLimiter(1000, "oldest", false, 0)

	// Send events concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				limiter.AllowEvent()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	received, _, _ := limiter.GetStats()
	if received != 1000 {
		t.Errorf("Expected 1000 received events, got %d", received)
	}
}

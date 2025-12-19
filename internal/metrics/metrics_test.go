package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func getCounterValue(counter prometheus.Counter) float64 {
	var m dto.Metric
	if err := counter.Write(&m); err != nil {
		return 0
	}
	return m.Counter.GetValue()
}

func getGaugeValue(gauge prometheus.Gauge) float64 {
	var m dto.Metric
	if err := gauge.Write(&m); err != nil {
		return 0
	}
	return m.Gauge.GetValue()
}

func TestEventsReceived(t *testing.T) {
	initial := getCounterValue(EventsReceived)
	EventsReceived.Inc()
	EventsReceived.Inc()
	final := getCounterValue(EventsReceived)

	if final-initial != 2 {
		t.Errorf("Expected 2 events received, got %.0f", final-initial)
	}
}

func TestEventsProcessed(t *testing.T) {
	initial := getCounterValue(EventsProcessed)
	EventsProcessed.Inc()
	final := getCounterValue(EventsProcessed)

	if final-initial != 1 {
		t.Errorf("Expected 1 event processed, got %.0f", final-initial)
	}
}

func TestEventsFiltered(t *testing.T) {
	initial := getCounterValue(EventsFiltered)
	EventsFiltered.Inc()
	final := getCounterValue(EventsFiltered)

	if final-initial != 1 {
		t.Errorf("Expected 1 event filtered, got %.0f", final-initial)
	}
}

func TestEventsDropped(t *testing.T) {
	initial := getCounterValue(EventsDropped)
	EventsDropped.Inc()
	final := getCounterValue(EventsDropped)

	if final-initial != 1 {
		t.Errorf("Expected 1 event dropped, got %.0f", final-initial)
	}
}

func TestRecordOperation(t *testing.T) {
	// Record a read operation with bytes
	RecordOperation("read", 1024)

	// Record a write operation
	RecordOperation("write", 2048)

	// Note: Testing counter vectors requires more complex metric extraction
	// For now, just verify no panics occur
}

func TestBytesReadWritten(t *testing.T) {
	initialRead := getCounterValue(BytesRead)
	initialWrite := getCounterValue(BytesWritten)

	RecordOperation("read", 1024)
	RecordOperation("write", 2048)

	finalRead := getCounterValue(BytesRead)
	finalWrite := getCounterValue(BytesWritten)

	if finalRead-initialRead != 1024 {
		t.Errorf("Expected 1024 bytes read, got %.0f", finalRead-initialRead)
	}

	if finalWrite-initialWrite != 2048 {
		t.Errorf("Expected 2048 bytes written, got %.0f", finalWrite-initialWrite)
	}
}

func TestRecordCacheHit(t *testing.T) {
	// Just verify no panics
	RecordCacheHit()
}

func TestRecordCacheMiss(t *testing.T) {
	// Just verify no panics
	RecordCacheMiss()
}

func TestMountsMonitored(t *testing.T) {
	MountsMonitored.Set(3)
	value := getGaugeValue(MountsMonitored)

	if value != 3 {
		t.Errorf("Expected 3 mounts monitored, got %.0f", value)
	}

	MountsMonitored.Set(5)
	value = getGaugeValue(MountsMonitored)

	if value != 5 {
		t.Errorf("Expected 5 mounts monitored, got %.0f", value)
	}
}

func TestRateLimitTokensAvailable(t *testing.T) {
	RateLimitTokensAvailable.Set(100)
	value := getGaugeValue(RateLimitTokensAvailable)

	if value != 100 {
		t.Errorf("Expected 100 tokens, got %.0f", value)
	}
}

func TestRecordOperationWithError(t *testing.T) {
	// Test with permission denied error (-13 = EACCES)
	RecordOperation("read", -13)

	// Should increment both total operations and failed operations
	// Note: We can't easily verify counter vector values without more complex helpers
	// This test mainly ensures no panics occur
}

func TestGetErrorName(t *testing.T) {
	tests := []struct {
		errno    int64
		expected string
	}{
		{-1, "EPERM"},
		{-2, "ENOENT"},
		{-13, "EACCES"},
		{-17, "EEXIST"},
		{-28, "ENOSPC"},
		{-122, "EDQUOT"},
		{-999, "OTHER"},
	}

	for _, tt := range tests {
		result := getErrorName(tt.errno)
		if result != tt.expected {
			t.Errorf("getErrorName(%d) = %s, want %s", tt.errno, result, tt.expected)
		}
	}
}

func TestRecordOperationSuccess(t *testing.T) {
	// Test successful read (positive bytes)
	RecordOperation("read", 4096)

	// Test successful write
	RecordOperation("write", 2048)

	// Verify no panics occur
}

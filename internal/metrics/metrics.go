package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for nfs-trail
var (
	// Event counters
	EventsReceived = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nfstrail_events_received_total",
		Help: "Total number of events received from eBPF",
	})

	EventsProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nfstrail_events_processed_total",
		Help: "Total number of events successfully processed",
	})

	EventsFiltered = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nfstrail_events_filtered_total",
		Help: "Total number of events filtered out (UID/operation filters)",
	})

	EventsDropped = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nfstrail_events_dropped_total",
		Help: "Total number of events dropped due to buffer/rate limits",
	})

	// Operations by type
	OperationsByType = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfstrail_operations_total",
			Help: "Total number of NFS operations by type",
		},
		[]string{"operation"},
	)

	// Bytes transferred
	BytesRead = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nfstrail_bytes_read_total",
		Help: "Total bytes read from NFS",
	})

	BytesWritten = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nfstrail_bytes_written_total",
		Help: "Total bytes written to NFS",
	})

	// Cache metrics
	CacheLookups = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nfstrail_cache_lookups_total",
			Help: "Total number of user/group cache lookups",
		},
		[]string{"result"}, // "hit" or "miss"
	)

	// Aggregation metrics
	EventsAggregated = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nfstrail_events_aggregated_total",
		Help: "Total number of individual events that were aggregated",
	})

	AggregatedEventsEmitted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nfstrail_aggregated_events_emitted_total",
		Help: "Total number of aggregated events emitted",
	})

	// Gauges for current state
	MountsMonitored = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "nfstrail_mounts_monitored",
		Help: "Number of NFS mounts currently being monitored",
	})

	// Rate limiting metrics
	RateLimitTokensAvailable = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "nfstrail_ratelimit_tokens_available",
		Help: "Number of rate limit tokens currently available",
	})

	// Histogram for event processing latency
	EventProcessingDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "nfstrail_event_processing_duration_seconds",
		Help:    "Time spent processing individual events",
		Buckets: prometheus.ExponentialBuckets(0.00001, 2, 10), // 10µs to 10ms
	})
)

// RecordOperation records a file operation with its details
func RecordOperation(operation string, bytes int64) {
	OperationsByType.WithLabelValues(operation).Inc()

	if operation == "read" && bytes > 0 {
		BytesRead.Add(float64(bytes))
	} else if operation == "write" && bytes > 0 {
		BytesWritten.Add(float64(bytes))
	}
}

// RecordCacheHit records a cache hit
func RecordCacheHit() {
	CacheLookups.WithLabelValues("hit").Inc()
}

// RecordCacheMiss records a cache miss
func RecordCacheMiss() {
	CacheLookups.WithLabelValues("miss").Inc()
}

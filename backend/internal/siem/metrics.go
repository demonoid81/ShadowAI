//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package siem

import "github.com/prometheus/client_golang/prometheus"

// SIEM Prometheus metrics. Label cardinality держим маленькой:
// только `sink` (v1: всегда "http"). Никаких endpoint/action/actor
// labels — они бы взорвали series count и потенциально leak'али
// identifiers.
var (
	// v1 per-request metrics (sink label: "http" or "http_batch").
	SIEMRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shadowai_siem_requests_total",
			Help: "Total SIEM mirror HTTP requests attempted (any outcome). Label sink=http_batch for async batched delivery.",
		},
		[]string{"sink"},
	)

	SIEMFailTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shadowai_siem_fail_total",
			Help: "SIEM mirror requests failed (non-2xx, network error).",
		},
		[]string{"sink"},
	)

	SIEMTimeoutTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shadowai_siem_timeout_total",
			Help: "SIEM mirror requests that timed out.",
		},
		[]string{"sink"},
	)

	SIEMLatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "shadowai_siem_latency_seconds",
			Help:    "SIEM mirror request latency.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"sink"},
	)

	// v1.1 async queue metrics.

	// SIEMQueueDepth tracks the current number of events waiting in the async queue.
	// Alert when sustained near QueueSize — indicates SIEM delivery lag or outage.
	SIEMQueueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "shadowai_siem_queue_depth",
		Help: "Current number of events waiting in the SIEM async delivery queue.",
	})

	// SIEMDroppedTotal counts events dropped due to backpressure (queue full).
	// Label policy: "drop_oldest" or "drop_newest".
	// Alert when non-zero — sustained drops mean SIEM delivery is too slow.
	SIEMDroppedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shadowai_siem_dropped_total",
			Help: "Events dropped because the async queue was full (backpressure). Label policy=drop_oldest|drop_newest.",
		},
		[]string{"policy"},
	)

	// SIEMBatchSize is a histogram of events per HTTP batch delivery.
	// Use to tune SIEM_BATCH_SIZE and SIEM_FLUSH_INTERVAL.
	SIEMBatchSize = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "shadowai_siem_batch_size",
		Help:    "Number of events delivered per HTTP batch request.",
		Buckets: []float64{1, 5, 10, 25, 50, 100, 250},
	})

	// SIEMRetryTotal counts batch delivery outcomes after retry logic.
	// Label outcome: "success" (eventually delivered) or "fail_all" (all retries exhausted).
	SIEMRetryTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shadowai_siem_retry_total",
			Help: "Batch delivery outcomes: outcome=success (delivered after ≥1 attempt) or fail_all (all retries exhausted).",
		},
		[]string{"outcome"},
	)

	// SIEMDeliveryLagSeconds tracks time from event enqueue to successful delivery.
	// Alert on p99 > SIEM_FLUSH_INTERVAL * MaxRetries — indicates persistent delay.
	SIEMDeliveryLagSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "shadowai_siem_delivery_lag_seconds",
		Help:    "Time from event enqueue to successful batch delivery (oldest event in batch).",
		Buckets: []float64{0.1, 0.5, 1, 2.5, 5, 10, 30, 60},
	})
)

func init() {
	prometheus.MustRegister(
		SIEMRequestsTotal, SIEMFailTotal, SIEMTimeoutTotal, SIEMLatencySeconds,
		SIEMQueueDepth, SIEMDroppedTotal, SIEMBatchSize, SIEMRetryTotal, SIEMDeliveryLagSeconds,
	)
}

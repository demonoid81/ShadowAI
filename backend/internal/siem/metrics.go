//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package siem

import "github.com/prometheus/client_golang/prometheus"

// SIEM Prometheus metrics. Label cardinality держим маленькой:
// только `sink` (v1: всегда "http"). Никаких endpoint/action/actor
// labels — они бы взорвали series count и потенциально leak'али
// identifiers.
var (
	SIEMRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shadowai_siem_requests_total",
			Help: "Total SIEM mirror requests attempted (any outcome).",
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
)

func init() {
	prometheus.MustRegister(SIEMRequestsTotal, SIEMFailTotal, SIEMTimeoutTotal, SIEMLatencySeconds)
}

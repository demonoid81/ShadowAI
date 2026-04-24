package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_http_requests_total",
		Help: "Total HTTP requests. Labels: method, route (Gorilla route template), status_code.",
	}, []string{"method", "route", "status_code"})

	httpDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "shadowai_http_duration_seconds",
		Help:    "HTTP request latency. Labels: method, route.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"method", "route"})
)

// PrometheusMetrics records HTTP request counts and latency using Gorilla mux
// route templates as the path label (prevents cardinality explosion from path params).
//
// Example labels:
//   method=GET route=/api/health status_code=200
//   method=POST route=/proxy/{provider}/ status_code=200
func PrometheusMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)

		route := routeTemplate(r)
		status := strconv.Itoa(sw.status)
		dur := time.Since(start).Seconds()

		httpRequestsTotal.WithLabelValues(r.Method, route, status).Inc()
		httpDurationSeconds.WithLabelValues(r.Method, route).Observe(dur)
	})
}

// routeTemplate returns the Gorilla mux route template for the request
// (e.g. "/proxy/{provider}/") or a bucketed fallback for unmatched paths.
// Using the template instead of the raw path prevents high-cardinality labels.
func routeTemplate(r *http.Request) string {
	if route := mux.CurrentRoute(r); route != nil {
		if tmpl, err := route.GetPathTemplate(); err == nil {
			return tmpl
		}
	}
	// Fallback: bucket unmatched paths to avoid cardinality explosion.
	return "unmatched"
}

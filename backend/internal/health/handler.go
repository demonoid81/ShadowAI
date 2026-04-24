// Package health provides HTTP handlers for Kubernetes liveness and readiness probes.
//
// Liveness  → GET /api/health   — "is the process alive?" (always 200 if server runs)
// Readiness → GET /api/ready    — "can the process serve traffic?" (200 if DB+Redis OK)
//
// Kubernetes wires:
//   livenessProbe:  GET /api/health  (failure → restart container)
//   readinessProbe: GET /api/ready   (failure → remove from Service endpoint)
//
// The readiness probe uses short timeouts (2s) to fail fast on degraded deps
// without blocking the probing kubelet.
package health

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

const probeTimeout = 2 * time.Second

// LivenessHandler responds 200 {"status":"ok"} unconditionally.
// The process being alive is sufficient for liveness.
func LivenessHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// ReadinessChecker holds the dependencies checked by the readiness probe.
type ReadinessChecker struct {
	DB    *sql.DB
	Redis redis.UniversalClient
}

type checkResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type readinessResponse struct {
	Ready  bool                    `json:"ready"`
	Checks map[string]checkResult  `json:"checks"`
}

// Ready probes DB and Redis with a short timeout and responds:
//   200 — both dependencies reachable
//   503 — one or more dependencies unreachable
func (h *ReadinessChecker) Ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
	defer cancel()

	checks := make(map[string]checkResult, 2)
	ready := true

	// DB ping.
	if err := h.DB.PingContext(ctx); err != nil {
		checks["db"] = checkResult{OK: false, Error: "ping failed"}
		ready = false
	} else {
		checks["db"] = checkResult{OK: true}
	}

	// Redis ping.
	if err := h.Redis.Ping(ctx).Err(); err != nil {
		checks["redis"] = checkResult{OK: false, Error: "ping failed"}
		ready = false
	} else {
		checks["redis"] = checkResult{OK: true}
	}

	resp := readinessResponse{Ready: ready, Checks: checks}
	w.Header().Set("Content-Type", "application/json")
	if ready {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(resp)
}

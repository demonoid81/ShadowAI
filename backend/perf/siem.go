//go:build enterprise

package perf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	"github.com/shadowai/backend/internal/siem"
)

// SIEMEnqueueNormal benchmarks AsyncBatchRecorder.Record() under normal conditions:
// SIEM endpoint is fast, queue has headroom. Measures non-blocking enqueue throughput.
func SIEMEnqueueNormal(r *Runner) BenchResult {
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	httpRec := siem.NewHTTPRecorder(srv.URL, "", 1*time.Second, false)
	rec := siem.NewAsyncBatchRecorder(httpRec, siem.AsyncBatchOptions{
		QueueSize:     10000,
		BatchSize:     100,
		FlushInterval: 10 * time.Millisecond,
		MaxRetries:    1,
		DropPolicy:    "drop_oldest",
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rec.Run(ctx)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
		srv.Close()
	}()

	actorID := "bench-user"
	ev := siem.Event{
		Action:     "proxy_request",
		ActorUserID: &actorID,
		Resource:   "bench-resource",
		StatusCode: 200,
		Success:    true,
	}

	return r.Run("SIEMEnqueueNormal",
		"AsyncBatchRecorder.Record() non-blocking enqueue (fast SIEM endpoint, headroom in queue)",
		func() (int64, error) {
			rec.Record(ctx, ev)
			return 0, nil
		})
}

// SIEMEnqueueBackpressure benchmarks queue behavior under saturation.
// SIEM endpoint is slow (100ms per batch), records are enqueued at max rate.
// Measures drop policy behavior: drop_oldest.
func SIEMEnqueueBackpressure(r *Runner) BenchResult {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond) // simulate slow SIEM
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	httpRec := siem.NewHTTPRecorder(srv.URL, "", 200*time.Millisecond, false)
	rec := siem.NewAsyncBatchRecorder(httpRec, siem.AsyncBatchOptions{
		QueueSize:     100, // deliberately small to trigger drops
		BatchSize:     10,
		FlushInterval: 50 * time.Millisecond,
		MaxRetries:    1,
		DropPolicy:    "drop_oldest",
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rec.Run(ctx)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	actorID2 := "bench-user"
	ev := siem.Event{
		Action:      "proxy_request",
		ActorUserID: &actorID2,
		Resource:    "bench-resource",
		StatusCode:  200,
		Success:     true,
	}

	result := r.Run("SIEMEnqueueBackpressure",
		"AsyncBatchRecorder.Record() under queue saturation (slow SIEM, drop_oldest policy)",
		func() (int64, error) {
			rec.Record(ctx, ev)
			return 0, nil
		})
	result.Notes = "Some drops expected (slow SIEM); check shadowai_siem_dropped_total in Prometheus"
	return result
}

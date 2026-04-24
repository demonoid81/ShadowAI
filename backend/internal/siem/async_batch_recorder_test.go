//go:build enterprise

package siem

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// capturedBatch holds all envelopes received by one HTTP POST.
type capturedBatch struct {
	Bodies []envelope
}

// mockBatchServer starts a test HTTP server that captures batches.
// If statusCode >= 400 on the first N requests, it returns that code.
func mockBatchServer(t *testing.T, statusCode int) (*httptest.Server, *batchCapture) {
	t.Helper()
	cap := &batchCapture{ch: make(chan capturedBatch, 50)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var envs []envelope
		_ = json.Unmarshal(body, &envs)
		cap.ch <- capturedBatch{Bodies: envs}
		w.WriteHeader(statusCode)
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

type batchCapture struct {
	ch chan capturedBatch
}

func (c *batchCapture) receive(t *testing.T, timeout time.Duration) capturedBatch {
	t.Helper()
	select {
	case b := <-c.ch:
		return b
	case <-time.After(timeout):
		t.Fatal("timeout waiting for batch delivery")
		return capturedBatch{}
	}
}

func newTestBatchRecorder(srv *httptest.Server, opts AsyncBatchOptions) *AsyncBatchRecorder {
	httpRec := NewHTTPRecorder(srv.URL, "", 2*time.Second, false)
	return NewAsyncBatchRecorder(httpRec, opts)
}

// ---------------------------------------------------------------------------
// ParseDropPolicy tests
// ---------------------------------------------------------------------------

func TestParseDropPolicy_Valid(t *testing.T) {
	cases := []struct {
		in   string
		want DropPolicy
	}{
		{"", DropOldest},
		{"drop_oldest", DropOldest},
		{"drop_newest", DropNewest},
	}
	for _, tc := range cases {
		got, err := ParseDropPolicy(tc.in)
		if err != nil {
			t.Errorf("ParseDropPolicy(%q): unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ParseDropPolicy(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseDropPolicy_Invalid(t *testing.T) {
	for _, bad := range []string{"DROP_OLDEST", "discard", "drop", "1"} {
		_, err := ParseDropPolicy(bad)
		if err == nil {
			t.Errorf("ParseDropPolicy(%q): expected error, got nil", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Record non-blocking tests
// ---------------------------------------------------------------------------

// TestAsyncBatchRecorder_RecordNonBlocking verifies that Record returns
// immediately without waiting for HTTP delivery.
func TestAsyncBatchRecorder_RecordNonBlocking(t *testing.T) {
	blocker := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocker
		io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() {
		close(blocker)
		srv.Close()
	})

	rec := newTestBatchRecorder(srv, AsyncBatchOptions{QueueSize: 100, BatchSize: 100})
	start := time.Now()
	// Enqueue 10 events — none should block even though HTTP is hanging.
	for i := 0; i < 10; i++ {
		rec.Record(context.Background(), Event{Action: "test", Resource: "x"})
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("Record blocked for %v — expected non-blocking enqueue", elapsed)
	}
}

// ---------------------------------------------------------------------------
// Batch delivery tests
// ---------------------------------------------------------------------------

// TestAsyncBatchRecorder_SizeTrigger verifies that a batch is flushed when
// BatchSize events have been enqueued.
func TestAsyncBatchRecorder_SizeTrigger(t *testing.T) {
	srv, cap := mockBatchServer(t, http.StatusOK)
	rec := newTestBatchRecorder(srv, AsyncBatchOptions{
		QueueSize:     100,
		BatchSize:     3,
		FlushInterval: 10 * time.Second, // long timer — should not trigger
		MaxRetries:    1,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go rec.Run(ctx)

	rec.Record(ctx, Event{Action: "a", Resource: "x"})
	rec.Record(ctx, Event{Action: "b", Resource: "x"})
	rec.Record(ctx, Event{Action: "c", Resource: "x"})

	batch := cap.receive(t, 2*time.Second)
	if len(batch.Bodies) != 3 {
		t.Errorf("batch size = %d, want 3", len(batch.Bodies))
	}
}

// TestAsyncBatchRecorder_TimerTrigger verifies that partial batches are
// flushed when the flush interval elapses.
func TestAsyncBatchRecorder_TimerTrigger(t *testing.T) {
	srv, cap := mockBatchServer(t, http.StatusOK)
	rec := newTestBatchRecorder(srv, AsyncBatchOptions{
		QueueSize:     100,
		BatchSize:     100,              // large — won't trigger by size
		FlushInterval: 50 * time.Millisecond, // short timer for test speed
		MaxRetries:    1,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go rec.Run(ctx)

	rec.Record(ctx, Event{Action: "timer-test", Resource: "x"})

	batch := cap.receive(t, 2*time.Second)
	if len(batch.Bodies) != 1 {
		t.Errorf("timer-triggered batch size = %d, want 1", len(batch.Bodies))
	}
	if batch.Bodies[0].Event.Action != "timer-test" {
		t.Errorf("event action = %q, want timer-test", batch.Bodies[0].Event.Action)
	}
}

// TestAsyncBatchRecorder_BatchContentsMatch verifies envelope content.
func TestAsyncBatchRecorder_BatchContentsMatch(t *testing.T) {
	srv, cap := mockBatchServer(t, http.StatusOK)
	rec := newTestBatchRecorder(srv, AsyncBatchOptions{
		QueueSize:     100,
		BatchSize:     2,
		FlushInterval: 10 * time.Second,
		MaxRetries:    1,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go rec.Run(ctx)

	actor := "u-admin"
	rec.Record(ctx, Event{ActorUserID: &actor, Action: "create", Resource: "hold"})
	rec.Record(ctx, Event{Action: "delete", Resource: "hold"})

	batch := cap.receive(t, 2*time.Second)
	if batch.Bodies[0].Source != "shadowai" {
		t.Errorf("source = %q, want shadowai", batch.Bodies[0].Source)
	}
	if batch.Bodies[0].Stream != "admin_event_logs" {
		t.Errorf("stream = %q, want admin_event_logs", batch.Bodies[0].Stream)
	}
	if batch.Bodies[0].Event.Action != "create" || batch.Bodies[1].Event.Action != "delete" {
		t.Errorf("events = %+v", batch.Bodies)
	}
}

// ---------------------------------------------------------------------------
// Retry tests
// ---------------------------------------------------------------------------

// TestAsyncBatchRecorder_RetryOnFailure verifies that a transient failure
// is retried and the batch is eventually delivered.
func TestAsyncBatchRecorder_RetryOnFailure(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		io.ReadAll(r.Body)
		if n < 2 { // first call fails
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	httpRec := NewHTTPRecorder(srv.URL, "", 2*time.Second, false)
	rec := NewAsyncBatchRecorder(httpRec, AsyncBatchOptions{
		QueueSize:     100,
		BatchSize:     1,
		FlushInterval: 10 * time.Second,
		MaxRetries:    3,
		RetryBase:     10 * time.Millisecond, // fast retry for tests
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go rec.Run(ctx)

	rec.Record(ctx, Event{Action: "retry-test", Resource: "x"})

	// Wait for 2+ HTTP calls (1 failure + 1 success).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Errorf("expected >= 2 HTTP calls (retry), got %d", calls.Load())
	}
}

// TestAsyncBatchRecorder_AllRetriesExhausted verifies that permanent failures
// are logged and do not block the worker.
func TestAsyncBatchRecorder_AllRetriesExhausted(t *testing.T) {
	srv, _ := mockBatchServer(t, http.StatusServiceUnavailable)
	rec := newTestBatchRecorder(srv, AsyncBatchOptions{
		QueueSize:     100,
		BatchSize:     1,
		FlushInterval: 10 * time.Second,
		MaxRetries:    2,
		RetryBase:     5 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go rec.Run(ctx)

	// Should not panic or block — permanent failure is logged + metric updated.
	rec.Record(ctx, Event{Action: "will-fail", Resource: "x"})
	// Give worker time to exhaust retries.
	time.Sleep(200 * time.Millisecond)
	// Test passes if we reach here (worker did not deadlock).
}

// ---------------------------------------------------------------------------
// Backpressure tests
// ---------------------------------------------------------------------------

// TestAsyncBatchRecorder_DropOldest verifies that when the queue is full,
// the oldest event is dropped and the newest is kept.
func TestAsyncBatchRecorder_DropOldest(t *testing.T) {
	// Use a queue of size 2, paused delivery to fill it.
	blocker := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocker
		io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() {
		close(blocker)
		srv.Close()
	})

	httpRec := NewHTTPRecorder(srv.URL, "", 2*time.Second, false)
	rec := NewAsyncBatchRecorder(httpRec, AsyncBatchOptions{
		QueueSize:     2,
		BatchSize:     10,
		FlushInterval: 50 * time.Millisecond,
		MaxRetries:    1,
		DropPolicy:    DropOldest,
	})
	// Don't start worker — queue will fill up.

	rec.Record(context.Background(), Event{Action: "first"})
	rec.Record(context.Background(), Event{Action: "second"})
	// Queue is now full (size 2).
	// This should drop "first" (oldest) and enqueue "third".
	rec.Record(context.Background(), Event{Action: "third"})

	// Verify queue contains "second" and "third", not "first".
	var found []string
	drain:
	for {
		select {
		case entry := <-rec.queue:
			found = append(found, entry.event.Action)
		default:
			break drain
		}
	}
	for _, a := range found {
		if a == "first" {
			t.Error("drop_oldest: 'first' should have been dropped, but it's in the queue")
		}
	}
	hasSnd := false
	hasTrd := false
	for _, a := range found {
		if a == "second" { hasSnd = true }
		if a == "third" { hasTrd = true }
	}
	if !hasSnd || !hasTrd {
		t.Errorf("drop_oldest: expected second+third in queue, got: %v", found)
	}
}

// TestAsyncBatchRecorder_DropNewest verifies that when the queue is full,
// the incoming event is dropped and the existing queue is preserved.
func TestAsyncBatchRecorder_DropNewest(t *testing.T) {
	httpRec := NewHTTPRecorder("http://127.0.0.1:1", "", 10*time.Millisecond, false)
	rec := NewAsyncBatchRecorder(httpRec, AsyncBatchOptions{
		QueueSize:     2,
		BatchSize:     10,
		FlushInterval: 10 * time.Second,
		MaxRetries:    1,
		DropPolicy:    DropNewest,
	})

	rec.Record(context.Background(), Event{Action: "first"})
	rec.Record(context.Background(), Event{Action: "second"})
	// Queue full: "third" should be dropped.
	rec.Record(context.Background(), Event{Action: "third"})

	var found []string
	drain2:
	for {
		select {
		case entry := <-rec.queue:
			found = append(found, entry.event.Action)
		default:
			break drain2
		}
	}
	for _, a := range found {
		if a == "third" {
			t.Error("drop_newest: 'third' should have been dropped, but it's in the queue")
		}
	}
}

// ---------------------------------------------------------------------------
// Graceful shutdown tests
// ---------------------------------------------------------------------------

// TestAsyncBatchRecorder_DrainOnShutdown verifies that events enqueued before
// ctx cancel are delivered before Run returns.
func TestAsyncBatchRecorder_DrainOnShutdown(t *testing.T) {
	var mu sync.Mutex
	var received []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var envs []envelope
		json.Unmarshal(body, &envs)
		mu.Lock()
		for _, e := range envs {
			received = append(received, e.Event.Action)
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	rec := newTestBatchRecorder(srv, AsyncBatchOptions{
		QueueSize:     100,
		BatchSize:     100,             // won't trigger by size
		FlushInterval: 10 * time.Second, // won't trigger by timer
		MaxRetries:    1,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rec.Run(ctx)
		close(done)
	}()

	rec.Record(ctx, Event{Action: "ev1"})
	rec.Record(ctx, Event{Action: "ev2"})
	rec.Record(ctx, Event{Action: "ev3"})

	// Cancel triggers drain.
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}

	mu.Lock()
	rcvd := received
	mu.Unlock()
	if len(rcvd) != 3 {
		t.Errorf("drained %d events, want 3: %v", len(rcvd), rcvd)
	}
}

// ---------------------------------------------------------------------------
// DefaultAsyncBatchOptions validation
// ---------------------------------------------------------------------------

func TestDefaultAsyncBatchOptions_Sane(t *testing.T) {
	opts := DefaultAsyncBatchOptions()
	if opts.QueueSize <= 0 {
		t.Errorf("QueueSize = %d, want > 0", opts.QueueSize)
	}
	if opts.BatchSize <= 0 {
		t.Errorf("BatchSize = %d, want > 0", opts.BatchSize)
	}
	if opts.FlushInterval <= 0 {
		t.Errorf("FlushInterval = %v, want > 0", opts.FlushInterval)
	}
	if opts.MaxRetries <= 0 {
		t.Errorf("MaxRetries = %d, want > 0", opts.MaxRetries)
	}
	if opts.DropPolicy == "" {
		t.Error("DropPolicy must not be empty")
	}
}

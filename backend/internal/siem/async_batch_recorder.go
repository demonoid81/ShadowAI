//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
//
// PR-S1.1: AsyncBatchRecorder — asynchronous queue + batch HTTP delivery
// for SIEM events.
//
// Architecture:
//
//	FanoutAdminRecorder.Record()
//	       ↓
//	  chan queueEntry  (bounded, backpressure policy on full)
//	       ↓
//	  worker goroutine (started via Run(ctx))
//	       ↓
//	  batch accumulation  → size trigger OR time trigger
//	       ↓
//	  HTTPRecorder.SendBatch()  → retry with exponential backoff
//
// Properties:
//   - Primary request path never waits on SIEM network.
//   - Queue memory is bounded (QueueSize * ~500B per event ≈ 500KB at 1000).
//   - Sustained SIEM outage is visible via metrics (queue_depth, dropped, retry).
//   - Graceful shutdown: Run(ctx) drains queue on ctx.Done() before returning.
package siem

import (
	"context"
	"log"
	"time"
)

// DropPolicy controls what happens when the async queue is full.
type DropPolicy string

const (
	// DropOldest discards the oldest queued event to make room for the new one.
	// Preserves the most recent event stream at the cost of old backlog.
	DropOldest DropPolicy = "drop_oldest"
	// DropNewest discards the incoming event and keeps the existing queue.
	// Preserves the oldest events (backlog) at the cost of recent events.
	DropNewest DropPolicy = "drop_newest"
)

// ParseDropPolicy validates and normalises a drop policy string.
// Empty string returns DropOldest (default).
func ParseDropPolicy(s string) (DropPolicy, error) {
	switch DropPolicy(s) {
	case "", DropOldest:
		return DropOldest, nil
	case DropNewest:
		return DropNewest, nil
	default:
		return "", &InvalidDropPolicyError{Value: s}
	}
}

// InvalidDropPolicyError is returned by ParseDropPolicy for unknown values.
type InvalidDropPolicyError struct{ Value string }

func (e *InvalidDropPolicyError) Error() string {
	return "unknown SIEM drop policy " + e.Value + `: must be "drop_oldest" or "drop_newest"`
}

// AsyncBatchOptions configures AsyncBatchRecorder.
type AsyncBatchOptions struct {
	// QueueSize is the capacity of the internal event queue.
	// Default: 1000. Must be > 0.
	QueueSize int
	// BatchSize is the maximum number of events per HTTP delivery.
	// Default: 50.
	BatchSize int
	// FlushInterval is the maximum time between flushes when the batch
	// does not fill up. Default: 5s.
	FlushInterval time.Duration
	// MaxRetries is the number of delivery attempts per batch.
	// Default: 3. A value of 1 means no retries (single attempt).
	MaxRetries int
	// RetryBase is the initial backoff delay between retries (doubles each attempt).
	// Default: 500ms.
	RetryBase time.Duration
	// DropPolicy controls what happens when the queue is full.
	// Default: DropOldest.
	DropPolicy DropPolicy
}

// DefaultAsyncBatchOptions returns production-ready defaults.
func DefaultAsyncBatchOptions() AsyncBatchOptions {
	return AsyncBatchOptions{
		QueueSize:     1000,
		BatchSize:     50,
		FlushInterval: 5 * time.Second,
		MaxRetries:    3,
		RetryBase:     500 * time.Millisecond,
		DropPolicy:    DropOldest,
	}
}

// queueEntry pairs an event with its enqueue timestamp for delivery lag tracking.
type queueEntry struct {
	event    Event
	queuedAt time.Time
}

// AsyncBatchRecorder implements Recorder. It enqueues events into a bounded
// channel and delivers them in batches from a background worker goroutine.
//
// Call Run(ctx) once from a dedicated goroutine to start the worker.
// Events enqueued before Run is called are delivered once Run starts.
type AsyncBatchRecorder struct {
	httpRec *HTTPRecorder
	opts    AsyncBatchOptions
	queue   chan queueEntry
}

// NewAsyncBatchRecorder creates an AsyncBatchRecorder. opts values ≤ 0 fall
// back to DefaultAsyncBatchOptions defaults.
func NewAsyncBatchRecorder(httpRec *HTTPRecorder, opts AsyncBatchOptions) *AsyncBatchRecorder {
	defaults := DefaultAsyncBatchOptions()
	if opts.QueueSize <= 0 {
		opts.QueueSize = defaults.QueueSize
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = defaults.BatchSize
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = defaults.FlushInterval
	}
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = defaults.MaxRetries
	}
	if opts.RetryBase <= 0 {
		opts.RetryBase = defaults.RetryBase
	}
	if opts.DropPolicy == "" {
		opts.DropPolicy = defaults.DropPolicy
	}
	return &AsyncBatchRecorder{
		httpRec: httpRec,
		opts:    opts,
		queue:   make(chan queueEntry, opts.QueueSize),
	}
}

// Record enqueues ev into the async queue without blocking the caller.
// If the queue is full, the configured DropPolicy is applied.
func (r *AsyncBatchRecorder) Record(_ context.Context, ev Event) {
	entry := queueEntry{event: ev, queuedAt: time.Now()}
	select {
	case r.queue <- entry:
		SIEMQueueDepth.Set(float64(len(r.queue)))
	default:
		r.applyDropPolicy(entry)
	}
}

func (r *AsyncBatchRecorder) applyDropPolicy(incoming queueEntry) {
	switch r.opts.DropPolicy {
	case DropOldest:
		// Discard oldest entry to make room for the new one.
		select {
		case old := <-r.queue:
			SIEMDroppedTotal.WithLabelValues(string(DropOldest)).Inc()
			log.Printf("siem: queue full (cap=%d), dropped oldest event action=%s",
				r.opts.QueueSize, old.event.Action)
		default:
		}
		select {
		case r.queue <- incoming:
		default:
			// Race: queue refilled between drain and insert — drop newest instead.
			SIEMDroppedTotal.WithLabelValues(string(DropNewest)).Inc()
		}
	default: // DropNewest
		SIEMDroppedTotal.WithLabelValues(string(DropNewest)).Inc()
		log.Printf("siem: queue full (cap=%d), dropped newest event action=%s",
			r.opts.QueueSize, incoming.event.Action)
	}
	SIEMQueueDepth.Set(float64(len(r.queue)))
}

// Run starts the batch delivery worker and blocks until ctx is cancelled.
// On cancellation the worker drains the queue and delivers any pending batch
// before returning.
//
// Lifecycle ctx governs when to stop accepting new events. HTTP delivery
// always uses context.Background() so that an in-flight batch is not
// interrupted by shutdown — i.e. events dequeued before cancellation are
// guaranteed to be delivered or retried to exhaustion.
//
// Call from a dedicated goroutine:
//
//	go siemRecorder.Run(ctx)
func (r *AsyncBatchRecorder) Run(ctx context.Context) {
	batch := make([]queueEntry, 0, r.opts.BatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		r.deliverWithRetry(batch)
		batch = batch[:0]
	}

	timer := time.NewTimer(r.opts.FlushInterval)
	defer timer.Stop()

	for {
		select {
		case entry := <-r.queue:
			SIEMQueueDepth.Set(float64(len(r.queue)))
			batch = append(batch, entry)
			if len(batch) >= r.opts.BatchSize {
				flush()
				resetTimer(timer, r.opts.FlushInterval)
			}

		case <-timer.C:
			flush()
			timer.Reset(r.opts.FlushInterval)

		case <-ctx.Done():
			// Drain remaining events from the queue.
		drain:
			for {
				select {
				case entry := <-r.queue:
					batch = append(batch, entry)
					if len(batch) >= r.opts.BatchSize {
						flush()
					}
				default:
					break drain
				}
			}
			flush()
			return
		}
	}
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// deliverWithRetry attempts to send batch to the SIEM endpoint with bounded
// exponential backoff. Always uses context.Background() for HTTP so that
// lifecycle ctx cancellation (shutdown) does not abort in-flight requests.
// Logs and records a metric on permanent failure.
func (r *AsyncBatchRecorder) deliverWithRetry(batch []queueEntry) {
	if r.httpRec == nil || len(batch) == 0 {
		return
	}

	events := make([]Event, len(batch))
	for i, e := range batch {
		events[i] = e.event
	}

	SIEMBatchSize.Observe(float64(len(batch)))

	var lastErr error
	for attempt := 0; attempt < r.opts.MaxRetries; attempt++ {
		// context.Background(): lifecycle ctx must not interrupt HTTP delivery.
		// The HTTP client's built-in Timeout covers per-request deadline.
		err := r.httpRec.SendBatch(context.Background(), events)
		if err == nil {
			lag := time.Since(batch[0].queuedAt).Seconds()
			SIEMDeliveryLagSeconds.Observe(lag)
			SIEMRetryTotal.WithLabelValues("success").Inc()
			return
		}
		lastErr = err
		if attempt < r.opts.MaxRetries-1 {
			time.Sleep(r.opts.RetryBase * (1 << uint(attempt))) // 500ms, 1s, 2s, ...
		}
	}

	SIEMRetryTotal.WithLabelValues("fail_all").Inc()
	log.Printf("siem: batch delivery failed after %d attempts (size=%d): %v",
		r.opts.MaxRetries, len(batch), lastErr)
}

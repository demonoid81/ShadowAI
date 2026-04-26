package perf

import (
	"bytes"
	"context"

	"github.com/shadowai/backend/internal/proxy/streaming"
)

// benchSSEStream is a canonical OpenAI-compat SSE stream for streaming benchmarks.
// Contains 5 events: role delta (empty), 3 content deltas, stop, [DONE].
var benchSSEStream = []byte(
	`data: {"id":"c-bench","model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"c-bench","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"The answer"},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"c-bench","model":"gpt-4o","choices":[{"index":0,"delta":{"content":" is clear"},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"c-bench","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"."},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"c-bench","model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n" +
		`data: [DONE]` + "\n\n")

// benchSSESanitizeStream is an SSE stream where one delta contains an email
// address that would trigger DLP sanitize. Used for sanitize-path benchmarks.
var benchSSESanitizeStream = []byte(
	`data: {"id":"c-san","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Contact "},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"c-san","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"user@example.com"},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"c-san","model":"gpt-4o","choices":[{"index":0,"delta":{"content":" for details."},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"c-san","model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n" +
		`data: [DONE]` + "\n\n")

// StreamingDecodeEmit benchmarks the full decode→emit round-trip for the
// OpenAI-compat adapter (bytes-identity allow path).
// This is the hot-path inner loop for every incremental streaming request.
func StreamingDecodeEmit(r *Runner) BenchResult {
	adapter, _ := streaming.AdapterForProvider("openai")
	ctx := context.Background()

	return r.Run("StreamingDecodeEmit",
		"OpenAICompatDecoder.Decode() + Emitter.Emit() round-trip (5 events, bytes-identity)",
		func() (int64, error) {
			var out bytes.Buffer
			var totalBytes int64
			err := adapter.Decoder.Decode(ctx, bytes.NewReader(benchSSEStream), func(ev streaming.Event) error {
				if emitErr := adapter.Emitter.Emit(ctx, &out, ev); emitErr != nil {
					return emitErr
				}
				totalBytes += int64(len(ev.RawBytes))
				return nil
			})
			// Verify bytes emitted to prevent compiler optimizing away work.
			if out.Len() == 0 {
				return 0, errBenchFailed
			}
			return totalBytes, err
		})
}

// StreamingDecodeOnly benchmarks just the decoder (no emit I/O).
func StreamingDecodeOnly(r *Runner) BenchResult {
	adapter, _ := streaming.AdapterForProvider("openai")
	ctx := context.Background()

	return r.Run("StreamingDecodeOnly",
		"OpenAICompatDecoder.Decode() only — JSON parse + event classification",
		func() (int64, error) {
			var eventCount int64
			err := adapter.Decoder.Decode(ctx, bytes.NewReader(benchSSEStream), func(ev streaming.Event) error {
				eventCount++
				return nil
			})
			if eventCount == 0 {
				return 0, errBenchFailed
			}
			return eventCount, err
		})
}

// StreamingEmitSanitized benchmarks EmitSanitized — the JSON re-encoding path
// that replaces delta.content with sanitized text.
// This fires when DLP/firewall triggers sanitize on a streaming delta.
func StreamingEmitSanitized(r *Runner) BenchResult {
	adapter, _ := streaming.AdapterForProvider("openai")
	ctx := context.Background()

	// Decode one delta_text event from the sanitize stream.
	var deltaEvent *streaming.Event
	_ = adapter.Decoder.Decode(ctx, bytes.NewReader(benchSSESanitizeStream), func(ev streaming.Event) error {
		if ev.Type == streaming.EventDeltaText && ev.Text == "user@example.com" {
			e := ev
			deltaEvent = &e
		}
		return nil
	})
	if deltaEvent == nil {
		// Fallback: use any delta_text event.
		_ = adapter.Decoder.Decode(ctx, bytes.NewReader(benchSSEStream), func(ev streaming.Event) error {
			if ev.Type == streaming.EventDeltaText && deltaEvent == nil {
				e := ev
				deltaEvent = &e
			}
			return nil
		})
	}

	sanitizedText := "[redacted:email]"

	return r.Run("StreamingEmitSanitized",
		"OpenAICompatEmitter.EmitSanitized() — JSON re-encode with content replacement (F7.5 sanitize path)",
		func() (int64, error) {
			if deltaEvent == nil {
				return 0, errBenchFailed
			}
			var out bytes.Buffer
			if err := adapter.Emitter.EmitSanitized(ctx, &out, *deltaEvent, sanitizedText); err != nil {
				return 0, err
			}
			if out.Len() == 0 {
				return 0, errBenchFailed
			}
			return int64(out.Len()), nil
		})
}

// StreamingEmitVsSanitize runs both allow (Emit) and sanitize (EmitSanitized) paths
// for direct comparison on the same event.
func StreamingEmitVsSanitize(r *Runner) BenchResult {
	adapter, _ := streaming.AdapterForProvider("openai")
	ctx := context.Background()

	// Decode a delta_text event.
	var deltaEvent *streaming.Event
	_ = adapter.Decoder.Decode(ctx, bytes.NewReader(benchSSEStream), func(ev streaming.Event) error {
		if ev.Type == streaming.EventDeltaText && deltaEvent == nil {
			e := ev
			deltaEvent = &e
		}
		return nil
	})

	sanitized := "replaced text"
	// Alternate between Emit and EmitSanitized to compare overhead.
	i := 0
	return r.Run("StreamingEmitVsSanitizeAlternating",
		"Alternating Emit/EmitSanitized on same event — overhead comparison",
		func() (int64, error) {
			if deltaEvent == nil {
				return 0, errBenchFailed
			}
			var out bytes.Buffer
			var err error
			if i%2 == 0 {
				err = adapter.Emitter.Emit(ctx, &out, *deltaEvent)
			} else {
				err = adapter.Emitter.EmitSanitized(ctx, &out, *deltaEvent, sanitized)
			}
			i++
			return int64(out.Len()), err
		})
}

package proxy

import (
	"sync"
	"testing"
)

// TestShouldUseIncrementalStream_NoSharedState — PR-F7.2.1 review
// fix #1 regression guard. Ранее Handler хранил fallback reason в
// shared mutable field → data race при concurrent streaming-запросах.
// После fix'а reason — request-local, возвращается из функции.
//
// PR-F7.3: compound marker helper удалён (TestComposeBufferedFallbackMarker
// тест удалён); вся fallback observability теперь в structured
// Outcome/FallbackReason полях (покрыто classifier tests в
// streaming_audit_test.go + end-to-end в handler_streaming_f73_test.go).
//
// Этот тест регрессионно проверяет, что сигнатура
// shouldUseIncrementalStream остаётся concurrent-safe.
func TestShouldUseIncrementalStream_NoSharedState(t *testing.T) {
	h := &Handler{streamingMode: "incremental"}
	// Capability не fallback (no CM+judge). Это изолирует тест на
	// provider-name branche.

	const iterations = 200
	type result struct {
		provider string
		ok       bool
		reason   string
	}

	results := make(chan result, iterations*2)
	var wg sync.WaitGroup
	for i := 0; i < iterations; i++ {
		wg.Add(2)
		// Supported provider (openai).
		go func() {
			defer wg.Done()
			_, ok, reason := h.shouldUseIncrementalStream("openai")
			results <- result{"openai", ok, reason}
		}()
		// Unsupported provider (cohere).
		go func() {
			defer wg.Done()
			_, ok, reason := h.shouldUseIncrementalStream("cohere")
			results <- result{"cohere", ok, reason}
		}()
	}
	wg.Wait()
	close(results)

	for r := range results {
		switch r.provider {
		case "openai":
			if !r.ok || r.reason != "" {
				t.Errorf("openai goroutine: ok=%v reason=%q; want ok=true reason=\"\" (race?)",
					r.ok, r.reason)
			}
		case "cohere":
			if r.ok {
				t.Errorf("cohere goroutine: ok=true; want false (unsupported)")
			}
			if r.reason != FallbackReasonUnsupportedProvider {
				t.Errorf("cohere goroutine: reason=%q; want %q (race likely)",
					r.reason, FallbackReasonUnsupportedProvider)
			}
		}
	}
}

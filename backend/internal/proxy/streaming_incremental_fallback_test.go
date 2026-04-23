package proxy

import (
	"sync"
	"testing"
)

// TestComposeBufferedFallbackMarker — PR-F7.2 review fix #3: compound
// marker сохраняет fallback-факт, даже если buffered path внутри
// отдал flag/block/sanitize.
func TestComposeBufferedFallbackMarker(t *testing.T) {
	cases := []struct {
		name           string
		original       string
		fallbackReason string
		want           string
	}{
		{"no_fallback_allow", "allowed", "", "allowed"},
		{"no_fallback_block", "blocked", "", "blocked"},
		{"fallback_clean_allow", "allowed", "judge_inspector", PolicyActionStreamingBufferedFallback},
		{"fallback_plus_block", "blocked", "judge_inspector", PolicyActionStreamingBufferedFallback + ":blocked"},
		{"fallback_plus_sanitize", "sanitized", "unsupported_provider", PolicyActionStreamingBufferedFallback + ":sanitized"},
		{"fallback_plus_flag", "flagged", "judge_inspector", PolicyActionStreamingBufferedFallback + ":flagged"},
		{"fallback_plus_empty_original", "", "judge_inspector", PolicyActionStreamingBufferedFallback + ":"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := composeBufferedFallbackMarker(c.original, c.fallbackReason)
			if got != c.want {
				t.Errorf("composeBufferedFallbackMarker(%q, %q) = %q, want %q",
					c.original, c.fallbackReason, got, c.want)
			}
		})
	}
}

// TestShouldUseIncrementalStream_NoSharedState — PR-F7.2 review fix
// #1 regression guard. Ранее Handler хранил fallback reason в shared
// mutable field → data race при concurrent streaming-запросах. После
// fix'а reason — request-local, возвращается из функции.
//
// Сценарий: один Handler вызывается concurrent'но с разными provider
// names, часть из которых unsupported. Каждый caller должен получить
// корректный fallback reason, соответствующий своему провайдеру, без
// leak'а между goroutine'ами.
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
		// Поток A: supported provider (openai). Ожидает ok=true,
		// reason="".
		go func() {
			defer wg.Done()
			_, ok, reason := h.shouldUseIncrementalStream("openai")
			results <- result{"openai", ok, reason}
		}()
		// Поток B: unsupported provider (cohere). Ожидает ok=false,
		// reason="unsupported_provider".
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

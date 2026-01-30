package proxy

import (
	"testing"
)

func TestCacheKey_Deterministic(t *testing.T) {
	msg := []byte(`[{"role":"user","content":"hello"}]`)
	k1 := CacheKey("openai", "gpt-4o", msg)
	k2 := CacheKey("openai", "gpt-4o", msg)

	if k1 != k2 {
		t.Errorf("same inputs produced different keys: %s vs %s", k1, k2)
	}
}

func TestCacheKey_DifferentInputs(t *testing.T) {
	msg1 := []byte(`[{"role":"user","content":"hello"}]`)
	msg2 := []byte(`[{"role":"user","content":"world"}]`)

	k1 := CacheKey("openai", "gpt-4o", msg1)
	k2 := CacheKey("openai", "gpt-4o", msg2)

	if k1 == k2 {
		t.Error("different messages produced same key")
	}
}

func TestCacheKey_DifferentProvider(t *testing.T) {
	msg := []byte(`[{"role":"user","content":"hello"}]`)
	k1 := CacheKey("openai", "gpt-4o", msg)
	k2 := CacheKey("anthropic", "gpt-4o", msg)

	if k1 == k2 {
		t.Error("different providers produced same key")
	}
}

func TestShouldCache(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		streaming  bool
		noCache    bool
		want       bool
	}{
		{"200 non-streaming", 200, false, false, true},
		{"201 non-streaming", 201, false, false, true},
		{"streaming", 200, true, false, false},
		{"no-cache header", 200, false, true, false},
		{"error status", 500, false, false, false},
		{"429 status", 429, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldCache(tt.statusCode, tt.streaming, tt.noCache)
			if got != tt.want {
				t.Errorf("ShouldCache(%d, %v, %v) = %v, want %v",
					tt.statusCode, tt.streaming, tt.noCache, got, tt.want)
			}
		})
	}
}

func TestNewSemanticCache_ZeroTTL(t *testing.T) {
	c := NewSemanticCache(newFakeRedis(), 0)
	if c != nil {
		t.Error("NewSemanticCache(0) should return nil")
	}
}

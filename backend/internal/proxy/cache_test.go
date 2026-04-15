package proxy

import (
	"context"
	"reflect"
	"time"
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

func TestSemanticCache_SetAndGet(t *testing.T) {
	c := NewSemanticCache(newFakeRedis(), time.Minute)
	if c == nil {
		t.Fatal("NewSemanticCache should not return nil for non-zero ttl")
	}

	ctx := context.Background()
	entry := &CacheEntry{
		StatusCode: 200,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       []byte(`{"message":"ok"}`),
		Provider:   "openai",
		Model:      "gpt-4o",
		CachedAt:   time.Date(2026, 2, 18, 0, 0, 0, 0, time.UTC),
	}

	key := CacheKey("openai", "gpt-4o", []byte(`[{"role":"user","content":"hello"}]`))
	if err := c.Set(ctx, key, entry); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got == nil {
		t.Fatal("Get() returned nil")
	}
	if got.StatusCode != entry.StatusCode {
		t.Fatalf("StatusCode = %d, want %d", got.StatusCode, entry.StatusCode)
	}
	if got.Provider != entry.Provider || got.Model != entry.Model {
		t.Fatalf("provider/model = %s/%s, want %s/%s", got.Provider, got.Model, entry.Provider, entry.Model)
	}
	if !reflect.DeepEqual(got.Headers, entry.Headers) {
		t.Fatalf("Headers = %#v, want %#v", got.Headers, entry.Headers)
	}
	if !reflect.DeepEqual(got.Body, entry.Body) {
		t.Fatalf("Body = %q, want %q", got.Body, entry.Body)
	}
}

func TestCacheKey_UserIsolation(t *testing.T) {
	msg := []byte(`[{"role":"user","content":"hello"}]`)
	k1 := CacheKeyForUser("user-a", "openai", "gpt-4o", msg)
	k2 := CacheKeyForUser("user-b", "openai", "gpt-4o", msg)

	if k1 == k2 {
		t.Fatal("cache keys should differ for different users")
	}
}

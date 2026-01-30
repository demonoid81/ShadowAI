package proxy

import (
	"context"
	"testing"
)

func TestRouter_ModelBased(t *testing.T) {
	reg := newTestRegistry(
		&testProvider{name: "openai", supportedModels: []string{"gpt-4o"}},
		&testProvider{name: "anthropic", supportedModels: []string{"claude-3-5-sonnet-20241022"}},
	)
	fr := newFakeRedis()
	ht := NewHealthTracker(fr)
	mapper := NewModelMapper(reg)
	router := NewRouter(reg, ht, mapper, StrategyCheapest, nil)

	results, err := router.Route(context.Background(), "gpt-4o")
	if err != nil {
		t.Fatalf("Route error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Route returned empty results")
	}
	if results[0].Name != "openai" {
		t.Errorf("first candidate = %q, want openai", results[0].Name)
	}
}

func TestRouter_CheapestStrategy(t *testing.T) {
	reg := newTestRegistry(
		&testProvider{name: "openai", supportedModels: []string{"gpt-4o"}},
		&testProvider{name: "ollama", supportedModels: []string{"llama3"}},
		&testProvider{name: "anthropic", supportedModels: []string{"claude-3"}},
	)
	fr := newFakeRedis()
	ht := NewHealthTracker(fr)
	mapper := NewModelMapper(reg)
	router := NewRouter(reg, ht, mapper, StrategyCheapest, nil)

	results, err := router.Route(context.Background(), "")
	if err != nil {
		t.Fatalf("Route error: %v", err)
	}
	if results[0].Name != "ollama" {
		t.Errorf("cheapest first = %q, want ollama", results[0].Name)
	}
}

func TestRouter_FastestStrategy(t *testing.T) {
	reg := newTestRegistry(
		&testProvider{name: "openai", supportedModels: []string{"gpt-4o"}},
		&testProvider{name: "anthropic", supportedModels: []string{"claude-3"}},
	)
	fr := newFakeRedis()
	ht := NewHealthTracker(fr)
	ctx := context.Background()

	// openai: avg 500ms, anthropic: avg 100ms
	ht.RecordSuccess(ctx, "openai", 500)
	ht.RecordSuccess(ctx, "anthropic", 100)

	mapper := NewModelMapper(reg)
	router := NewRouter(reg, ht, mapper, StrategyFastest, nil)

	results, err := router.Route(ctx, "")
	if err != nil {
		t.Fatalf("Route error: %v", err)
	}
	if results[0].Name != "anthropic" {
		t.Errorf("fastest first = %q, want anthropic", results[0].Name)
	}
}

func TestRouter_RoundRobin(t *testing.T) {
	reg := newTestRegistry(
		&testProvider{name: "openai", supportedModels: []string{"gpt-4o"}},
		&testProvider{name: "anthropic", supportedModels: []string{"claude-3"}},
	)
	fr := newFakeRedis()
	ht := NewHealthTracker(fr)
	mapper := NewModelMapper(reg)
	router := NewRouter(reg, ht, mapper, StrategyRoundRobin, nil)

	// Call Route twice — first candidates should differ
	r1, _ := router.Route(context.Background(), "")
	r2, _ := router.Route(context.Background(), "")

	if r1[0].Name == r2[0].Name {
		t.Errorf("round-robin produced same first candidate: %s", r1[0].Name)
	}
}

func TestRouter_EmptyRegistry(t *testing.T) {
	reg := NewRegistry()
	fr := newFakeRedis()
	ht := NewHealthTracker(fr)
	mapper := NewModelMapper(reg)
	router := NewRouter(reg, ht, mapper, StrategyCheapest, nil)

	_, err := router.Route(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty registry, got nil")
	}
}

func TestRouter_FallbackOrder(t *testing.T) {
	reg := newTestRegistry(
		&testProvider{name: "openai", supportedModels: []string{"gpt-4o"}},
		&testProvider{name: "anthropic", supportedModels: []string{"claude-3"}},
		&testProvider{name: "groq", supportedModels: []string{"llama-3"}},
	)
	fr := newFakeRedis()
	ht := NewHealthTracker(fr)
	mapper := NewModelMapper(reg)
	router := NewRouter(reg, ht, mapper, StrategyCheapest, []string{"anthropic", "groq", "openai"})

	results, err := router.Route(context.Background(), "")
	if err != nil {
		t.Fatalf("Route error: %v", err)
	}
	if results[0].Name != "anthropic" {
		t.Errorf("fallback order first = %q, want anthropic", results[0].Name)
	}
	if results[1].Name != "groq" {
		t.Errorf("fallback order second = %q, want groq", results[1].Name)
	}
	if results[2].Name != "openai" {
		t.Errorf("fallback order third = %q, want openai", results[2].Name)
	}
}

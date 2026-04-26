//go:build enterprise

package perf

import (
	"context"
	"time"

	"github.com/shadowai/backend/internal/governance"
)

// perfFakeGovRepo is a minimal governance.Repository for benchmarks.
type perfFakeGovRepo struct {
	policy  *governance.Policy
	latency time.Duration // simulated DB round-trip
}

func (r *perfFakeGovRepo) GetActive(_ context.Context, _ string) (*governance.Policy, error) {
	if r.latency > 0 {
		time.Sleep(r.latency)
	}
	return r.policy, nil
}

func (r *perfFakeGovRepo) Upsert(_ context.Context, p *governance.Policy, _, _ string) (*governance.Policy, error) {
	return p, nil
}

func benchAllowlistPolicy() *governance.Policy {
	return &governance.Policy{
		ID:   "bench-policy",
		Mode: governance.ModeAllowlistStrict,
		Rules: []governance.ProviderRule{
			{Provider: "openai", Models: []string{"gpt-4o", "gpt-4o-mini"}},
			{Provider: "anthropic", Models: []string{"claude-3-sonnet"}},
		},
		IsActive: true,
	}
}

// GovernanceCacheHit benchmarks the hot path: GetActive with pre-populated cache.
func GovernanceCacheHit(r *Runner) BenchResult {
	fakeRepo := &perfFakeGovRepo{policy: benchAllowlistPolicy()}
	cached := governance.NewCachingRepository(fakeRepo)
	ctx := context.Background()
	_, _ = cached.GetActive(ctx, "org-bench") // warm cache

	return r.Run("GovernanceCacheHit",
		"CachingRepository.GetActive() with warm in-process cache (zero DB calls)",
		func() (int64, error) {
			_, err := cached.GetActive(ctx, "org-bench")
			return 0, err
		})
}

// GovernanceCacheMiss benchmarks the cold-cache path with simulated DB latency.
func GovernanceCacheMiss(r *Runner) BenchResult {
	fakeRepo := &perfFakeGovRepo{policy: benchAllowlistPolicy(), latency: 1 * time.Millisecond}
	ctx := context.Background()

	return r.Run("GovernanceCacheMiss",
		"CachingRepository.GetActive() cold cache + ~1ms simulated DB round-trip",
		func() (int64, error) {
			// Fresh CachingRepository per call → always cold cache.
			cached := governance.NewCachingRepository(fakeRepo)
			_, err := cached.GetActive(ctx, "org-bench")
			return 0, err
		})
}

// GovernanceEvaluate benchmarks Service.Evaluate with allowlist_strict + cached policy.
func GovernanceEvaluate(r *Runner) BenchResult {
	fakeRepo := &perfFakeGovRepo{policy: benchAllowlistPolicy()}
	cached := governance.NewCachingRepository(fakeRepo)
	svc := governance.NewService(cached)
	ctx := context.Background()
	// Warm cache.
	_, _ = svc.Evaluate(ctx, "org-bench", "user", "engineering", "standard", "openai", "gpt-4o")

	return r.Run("GovernanceEvaluate",
		"Service.Evaluate() allowlist_strict with cached policy (allow path, no DB)",
		func() (int64, error) {
			_, err := svc.Evaluate(ctx, "org-bench", "user", "engineering", "standard", "openai", "gpt-4o")
			return 0, err
		})
}

// GovernanceEvaluateDeny benchmarks the deny path (unknown provider).
func GovernanceEvaluateDeny(r *Runner) BenchResult {
	fakeRepo := &perfFakeGovRepo{policy: benchAllowlistPolicy()}
	cached := governance.NewCachingRepository(fakeRepo)
	svc := governance.NewService(cached)
	ctx := context.Background()
	_, _ = svc.Evaluate(ctx, "org-bench", "user", "engineering", "standard", "openai", "gpt-4o")

	return r.Run("GovernanceEvaluateDeny",
		"Service.Evaluate() allowlist_strict deny path (unknown_provider, cached policy)",
		func() (int64, error) {
			_, err := svc.Evaluate(ctx, "org-bench", "user", "engineering", "standard", "cohere", "command-r")
			return 0, err
		})
}

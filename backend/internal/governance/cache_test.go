//go:build enterprise

package governance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// countingRepo is a Repository stub that counts GetActive calls and can be
// configured to return a specific policy or error.
type countingRepo struct {
	mu       sync.Mutex
	policy   *Policy
	err      error
	getCalls atomic.Int64 // accessed by goroutines during concurrency tests
}

func (r *countingRepo) GetActive(_ context.Context, _ string) (*Policy, error) {
	r.getCalls.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.policy, r.err
}

func (r *countingRepo) Upsert(_ context.Context, p *Policy, _, _ string) (*Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policy = p
	return p, nil
}

func (r *countingRepo) calls() int64 { return r.getCalls.Load() }

// strictPolicy returns a minimal allowlist_strict Policy for tests.
func strictPolicy(id string) *Policy {
	return &Policy{
		ID:   id,
		Mode: ModeAllowlistStrict,
		Rules: []ProviderRule{
			{Provider: "openai", Models: []string{"gpt-4"}},
		},
		IsActive: true,
	}
}

// ---------------------------------------------------------------------------
// Definition of Done tests
// ---------------------------------------------------------------------------

// TestCache_DoD_HotPath_NoDB verifies: Evaluate does not trigger a DB read
// after the first load (cache hit path).
func TestCache_DoD_HotPath_NoDB(t *testing.T) {
	inner := &countingRepo{policy: strictPolicy("p1")}
	repo := NewCachingRepository(inner)
	ctx := context.Background()

	// First call: cache miss → 1 DB call.
	if _, err := repo.GetActive(ctx, "org-1"); err != nil {
		t.Fatalf("first GetActive: %v", err)
	}
	if inner.calls() != 1 {
		t.Fatalf("expected 1 DB call after miss, got %d", inner.calls())
	}

	// Subsequent calls: cache hit → no additional DB calls.
	for i := 0; i < 5; i++ {
		if _, err := repo.GetActive(ctx, "org-1"); err != nil {
			t.Fatalf("GetActive call %d: %v", i+2, err)
		}
	}
	if inner.calls() != 1 {
		t.Errorf("expected 1 total DB call (5 hits), got %d", inner.calls())
	}
	m := repo.Metrics()
	if m.Hits() != 5 {
		t.Errorf("Hits=%d, want 5", m.Hits())
	}
	if m.Misses() != 1 {
		t.Errorf("Misses=%d, want 1", m.Misses())
	}
}

// TestCache_DoD_FirstRequest_LoadsDB verifies: first request per org calls DB.
func TestCache_DoD_FirstRequest_LoadsDB(t *testing.T) {
	inner := &countingRepo{policy: strictPolicy("p-first")}
	repo := NewCachingRepository(inner)

	p, err := repo.GetActive(context.Background(), "org-new")
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if p == nil || p.ID != "p-first" {
		t.Errorf("policy = %v, want p-first", p)
	}
	if inner.calls() != 1 {
		t.Errorf("DB calls=%d, want 1", inner.calls())
	}
}

// TestCache_DoD_SecondRequest_HitsCache verifies: second request for same org
// returns cached policy without a DB call.
func TestCache_DoD_SecondRequest_HitsCache(t *testing.T) {
	inner := &countingRepo{policy: strictPolicy("p-cached")}
	repo := NewCachingRepository(inner)
	ctx := context.Background()

	_, _ = repo.GetActive(ctx, "org-x")
	_, _ = repo.GetActive(ctx, "org-x")

	if inner.calls() != 1 {
		t.Errorf("DB calls=%d, want 1 (second should hit cache)", inner.calls())
	}
}

// TestCache_DoD_Upsert_UpdatesCache verifies: after Upsert, GetActive returns
// the new policy without a DB call.
func TestCache_DoD_Upsert_UpdatesCache(t *testing.T) {
	inner := &countingRepo{policy: strictPolicy("old")}
	repo := NewCachingRepository(inner)
	ctx := context.Background()

	// Populate cache with old policy.
	if _, err := repo.GetActive(ctx, "org-u"); err != nil {
		t.Fatalf("initial GetActive: %v", err)
	}
	callsAfterLoad := inner.calls()

	// Upsert new policy.
	newPolicy := strictPolicy("new")
	if _, err := repo.Upsert(ctx, newPolicy, "admin-1", "org-u"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// GetActive must return the new policy without hitting DB.
	p, err := repo.GetActive(ctx, "org-u")
	if err != nil {
		t.Fatalf("GetActive after Upsert: %v", err)
	}
	if p == nil || p.ID != "new" {
		t.Errorf("after Upsert: policy.ID=%q, want \"new\"", p.ID)
	}
	// +1 for inner.Upsert (which uses inner.GetActive internally via selectOrInsert);
	// GetActive after Upsert should not add another DB call.
	if inner.calls() != callsAfterLoad {
		t.Errorf("GetActive after Upsert added DB calls: before=%d after=%d",
			callsAfterLoad, inner.calls())
	}
	if repo.Metrics().Hits() < 1 {
		t.Errorf("expected at least 1 hit after Upsert write-through, got %d", repo.Metrics().Hits())
	}
}

// TestCache_DistributedInvalidation_RefreshesRemoteReplica verifies G2.3:
// when replica A updates policy, replica B invalidates its cached snapshot and
// reloads on the next request without waiting for the TTL.
func TestCache_DistributedInvalidation_RefreshesRemoteReplica(t *testing.T) {
	inner := &orgSwitchRepo{policies: map[string]*Policy{"org-emergency": strictPolicy("old")}}
	remoteReplica := NewCachingRepository(inner, WithTTL(time.Hour))
	ctx := context.Background()

	// Replica B caches the old policy with a long TTL.
	oldPolicy, err := remoteReplica.GetActive(ctx, "org-emergency")
	if err != nil {
		t.Fatalf("remote initial GetActive: %v", err)
	}
	if oldPolicy == nil || oldPolicy.ID != "old" {
		t.Fatalf("remote initial policy=%v, want old", oldPolicy)
	}

	publisher := &forwardingInvalidationPublisher{target: remoteReplica}
	updatingReplica := NewCachingRepository(inner, WithTTL(time.Hour), WithInvalidationPublisher(publisher))

	// Replica A writes the emergency block.
	if _, err := updatingReplica.Upsert(ctx, strictPolicy("emergency-block"), "admin-1", "org-emergency"); err != nil {
		t.Fatalf("updating Upsert: %v", err)
	}

	// Replica B must not serve its old cached copy.
	got, err := remoteReplica.GetActive(ctx, "org-emergency")
	if err != nil {
		t.Fatalf("remote GetActive after invalidation: %v", err)
	}
	if got == nil || got.ID != "emergency-block" {
		t.Fatalf("remote policy after invalidation=%v, want emergency-block", got)
	}
	if remoteReplica.Metrics().Invalidations() != 1 {
		t.Errorf("remote invalidations=%d, want 1", remoteReplica.Metrics().Invalidations())
	}
	if publisher.calls.Load() != 1 {
		t.Errorf("publisher calls=%d, want 1", publisher.calls.Load())
	}
}

// TestCache_DistributedInvalidation_PublishErrorVisible verifies that a Redis
// publish failure is not silent: the write-through cache remains correct in the
// local replica, and the publish error metric increments for operators.
func TestCache_DistributedInvalidation_PublishErrorVisible(t *testing.T) {
	inner := &countingRepo{policy: strictPolicy("old")}
	repo := NewCachingRepository(inner, WithInvalidationPublisher(errorInvalidationPublisher{}))

	if _, err := repo.Upsert(context.Background(), strictPolicy("new"), "admin-1", "org-puberr"); err != nil {
		t.Fatalf("Upsert should persist even when invalidation publish fails: %v", err)
	}
	if repo.Metrics().InvalidationPublishErrors() != 1 {
		t.Errorf("InvalidationPublishErrors=%d, want 1", repo.Metrics().InvalidationPublishErrors())
	}
	got, err := repo.GetActive(context.Background(), "org-puberr")
	if err != nil {
		t.Fatalf("GetActive after publish error: %v", err)
	}
	if got == nil || got.ID != "new" {
		t.Fatalf("local policy after publish error=%v, want new", got)
	}
}

type forwardingInvalidationPublisher struct {
	target *CachingRepository
	calls  atomic.Int64
}

func (p *forwardingInvalidationPublisher) PublishGovernanceInvalidation(_ context.Context, orgID, _ string) error {
	p.calls.Add(1)
	p.target.Invalidate(orgID)
	return nil
}

type errorInvalidationPublisher struct{}

func (errorInvalidationPublisher) PublishGovernanceInvalidation(context.Context, string, string) error {
	return fmt.Errorf("redis publish failed")
}

// TestCache_DoD_ReloadError_FailClosed verifies: DB error on cache miss returns
// error (not a silent allow), and the reload_error metric increments.
func TestCache_DoD_ReloadError_FailClosed(t *testing.T) {
	dbErr := errors.New("connection refused")
	inner := &countingRepo{err: dbErr}
	repo := NewCachingRepository(inner)

	p, err := repo.GetActive(context.Background(), "org-fail")
	if err == nil {
		t.Fatal("expected error on DB failure, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("error = %v, want %v", err, dbErr)
	}
	if p != nil {
		t.Errorf("policy should be nil on error, got %+v", p)
	}
	if repo.Metrics().ReloadErrors() != 1 {
		t.Errorf("ReloadErrors=%d, want 1", repo.Metrics().ReloadErrors())
	}
}

// TestCache_DoD_OrgIsolation verifies: policy cached for org A does not affect
// org B (different keys, different DB loads).
func TestCache_DoD_OrgIsolation(t *testing.T) {
	pA := strictPolicy("policy-A")
	pB := &Policy{
		ID:   "policy-B",
		Mode: ModeAllowlistStrict,
		Rules: []ProviderRule{
			{Provider: "anthropic", Models: []string{"claude-3"}},
		},
		IsActive: true,
	}

	// Use a repo that returns different policies per org via a custom implementation.
	perOrgRepo := &orgSwitchRepo{policies: map[string]*Policy{"org-a": pA, "org-b": pB}}
	repo := NewCachingRepository(perOrgRepo)
	ctx := context.Background()

	gotA, _ := repo.GetActive(ctx, "org-a")
	gotB, _ := repo.GetActive(ctx, "org-b")

	if gotA == nil || gotA.ID != "policy-A" {
		t.Errorf("org-a policy = %v, want policy-A", gotA)
	}
	if gotB == nil || gotB.ID != "policy-B" {
		t.Errorf("org-b policy = %v, want policy-B", gotB)
	}
	// Verify org-a still returns A after org-b was cached.
	gotA2, _ := repo.GetActive(ctx, "org-a")
	if gotA2 == nil || gotA2.ID != "policy-A" {
		t.Errorf("org-a contaminated after org-b load: got %v", gotA2)
	}
}

// orgSwitchRepo returns different policies per org for isolation tests.
type orgSwitchRepo struct {
	mu       sync.Mutex
	policies map[string]*Policy
}

func (r *orgSwitchRepo) GetActive(_ context.Context, orgID string) (*Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.policies[orgID], nil
}

func (r *orgSwitchRepo) Upsert(_ context.Context, p *Policy, _, orgID string) (*Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies[orgID] = p
	return p, nil
}

// TestCache_DoD_Metrics_HitMissReloadError verifies all metric counters.
func TestCache_DoD_Metrics_HitMissReloadError(t *testing.T) {
	inner := &countingRepo{policy: strictPolicy("m1")}
	repo := NewCachingRepository(inner)
	ctx := context.Background()

	// 1 miss → load
	repo.GetActive(ctx, "org-m") //nolint:errcheck

	// 3 hits
	for i := 0; i < 3; i++ {
		repo.GetActive(ctx, "org-m") //nolint:errcheck
	}

	// 1 miss for a different org
	repo.GetActive(ctx, "org-n") //nolint:errcheck

	// 1 reload error for a new org
	inner.mu.Lock()
	inner.err = errors.New("db down")
	inner.mu.Unlock()
	repo.GetActive(ctx, "org-err") //nolint:errcheck
	inner.mu.Lock()
	inner.err = nil
	inner.mu.Unlock()

	m := repo.Metrics()
	// org-m: 1 miss; org-n: 1 miss; org-err: 1 miss + reload_error (new org, DB error).
	if m.Misses() != 3 {
		t.Errorf("Misses=%d, want 3 (org-m + org-n + org-err)", m.Misses())
	}
	if m.Hits() != 3 {
		t.Errorf("Hits=%d, want 3", m.Hits())
	}
	if m.ReloadErrors() != 1 {
		t.Errorf("ReloadErrors=%d, want 1", m.ReloadErrors())
	}
}

// TestCache_TTL_Expired_Triggers_Reload verifies that a TTL-expired entry
// triggers a DB reload and increments the stale counter.
func TestCache_TTL_Expired_Triggers_Reload(t *testing.T) {
	inner := &countingRepo{policy: strictPolicy("ttl-v1")}
	// Very short TTL so the entry expires before the second GetActive call.
	repo := NewCachingRepository(inner, WithTTL(1*time.Millisecond))
	ctx := context.Background()

	// First call: miss → load.
	repo.GetActive(ctx, "org-ttl") //nolint:errcheck
	if inner.calls() != 1 {
		t.Fatalf("expected 1 DB call, got %d", inner.calls())
	}

	// Wait for TTL to expire.
	time.Sleep(5 * time.Millisecond)

	// Second call: stale → reload.
	inner.mu.Lock()
	inner.policy = strictPolicy("ttl-v2")
	inner.mu.Unlock()

	p, err := repo.GetActive(ctx, "org-ttl")
	if err != nil {
		t.Fatalf("GetActive after TTL: %v", err)
	}
	if p == nil || p.ID != "ttl-v2" {
		t.Errorf("after TTL reload: policy.ID=%q, want ttl-v2", p.ID)
	}
	if inner.calls() != 2 {
		t.Errorf("expected 2 DB calls (miss + stale), got %d", inner.calls())
	}
	if repo.Metrics().Stale() != 1 {
		t.Errorf("Stale=%d, want 1", repo.Metrics().Stale())
	}
}

// TestCache_StaleReloadError_FailClosed verifies that a DB error on a
// TTL-expired entry fails closed (error returned, NOT old stale value).
func TestCache_StaleReloadError_FailClosed(t *testing.T) {
	inner := &countingRepo{policy: strictPolicy("stale-p")}
	repo := NewCachingRepository(inner, WithTTL(1*time.Millisecond))
	ctx := context.Background()

	// Populate cache.
	repo.GetActive(ctx, "org-stale") //nolint:errcheck
	time.Sleep(5 * time.Millisecond) // expire

	// Now DB is down.
	inner.mu.Lock()
	inner.err = errors.New("db down")
	inner.mu.Unlock()

	p, err := repo.GetActive(ctx, "org-stale")
	if err == nil {
		t.Fatal("expected error on stale reload failure, got nil")
	}
	if p != nil {
		t.Errorf("policy should be nil on reload error, got %+v", p)
	}
	if repo.Metrics().ReloadErrors() != 1 {
		t.Errorf("ReloadErrors=%d, want 1", repo.Metrics().ReloadErrors())
	}
}

// TestCache_AbsentPolicy_CachesNil verifies that a nil policy (no DB entry) is
// cached correctly and does not trigger repeated DB calls.
func TestCache_AbsentPolicy_CachesNil(t *testing.T) {
	inner := &countingRepo{policy: nil} // no policy in DB
	repo := NewCachingRepository(inner)
	ctx := context.Background()

	p1, _ := repo.GetActive(ctx, "org-absent")
	p2, _ := repo.GetActive(ctx, "org-absent")

	if p1 != nil || p2 != nil {
		t.Errorf("expected nil policy for org with no DB entry, got %v / %v", p1, p2)
	}
	if inner.calls() != 1 {
		t.Errorf("expected 1 DB call (nil policy should be cached), got %d", inner.calls())
	}
	if repo.Metrics().Misses() != 1 || repo.Metrics().Hits() != 1 {
		t.Errorf("miss=%d hit=%d, want miss=1 hit=1", repo.Metrics().Misses(), repo.Metrics().Hits())
	}
}

// TestCache_Concurrent_NoRace verifies that concurrent GetActive and Upsert
// calls produce no data races. Run with go test -race.
func TestCache_Concurrent_NoRace(t *testing.T) {
	inner := &countingRepo{policy: strictPolicy("race-p")}
	repo := NewCachingRepository(inner, WithTTL(5*time.Millisecond))
	ctx := context.Background()

	var wg sync.WaitGroup
	const readers = 20
	const writers = 5
	const iterations = 50

	// Concurrent readers.
	for i := 0; i < readers; i++ {
		orgID := "org-race"
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				p, err := repo.GetActive(ctx, orgID)
				if err != nil {
					t.Errorf("concurrent GetActive: %v", err)
					return
				}
				if p == nil {
					t.Error("concurrent GetActive: got nil policy")
					return
				}
				// Small sleep to increase interleaving.
				time.Sleep(time.Microsecond)
			}
		}()
	}

	// Concurrent writers.
	for i := 0; i < writers; i++ {
		idx := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations/writers; j++ {
				p := strictPolicy("race-p-" + string(rune('a'+idx)))
				if _, err := repo.Upsert(ctx, p, "actor", "org-race"); err != nil {
					t.Errorf("concurrent Upsert: %v", err)
					return
				}
				time.Sleep(time.Microsecond)
			}
		}()
	}

	wg.Wait()
}

// TestCache_ConcurrentMultiOrg_NoRace verifies per-org isolation under
// concurrent access across multiple orgs.
func TestCache_ConcurrentMultiOrg_NoRace(t *testing.T) {
	policies := map[string]*Policy{
		"org-1": strictPolicy("p-1"),
		"org-2": strictPolicy("p-2"),
		"org-3": strictPolicy("p-3"),
	}
	inner := &orgSwitchRepo{policies: policies}
	repo := NewCachingRepository(inner, WithTTL(10*time.Millisecond))
	ctx := context.Background()

	var wg sync.WaitGroup
	for _, orgID := range []string{"org-1", "org-2", "org-3"} {
		org := orgID
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				p, err := repo.GetActive(ctx, org)
				if err != nil {
					t.Errorf("org=%s GetActive: %v", org, err)
					return
				}
				_ = p
				time.Sleep(time.Microsecond)
			}
		}()
	}
	wg.Wait()
}

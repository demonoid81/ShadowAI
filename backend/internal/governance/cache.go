//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package governance

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// defaultCacheTTL is the maximum age of a cached policy snapshot before it is
// considered stale and reloaded from the DB. This is a TTL fallback for
// multi-replica deployments where another replica's Upsert does not reach this
// in-process cache. Same-replica Upsert always writes through immediately.
const defaultCacheTTL = 60 * time.Second

// cacheEntry is an immutable snapshot of a governance policy at load time.
// The *Policy pointer must never be mutated after the entry is stored in the
// cache; concurrent readers hold only the pointer and read fields directly.
type cacheEntry struct {
	policy   *Policy // nil → no policy configured (governance disabled)
	loadedAt time.Time
}

// CacheMetrics holds per-instance atomic counters for the policy cache.
// Tests assert these directly; Prometheus mirrors them via package-level vars.
type CacheMetrics struct {
	hits                      atomic.Int64
	misses                    atomic.Int64
	reloadErrors              atomic.Int64
	stale                     atomic.Int64
	invalidations             atomic.Int64
	invalidationPublishErrors atomic.Int64
}

// Hits returns the cumulative count of cache hits (valid snapshot, no DB read).
func (m *CacheMetrics) Hits() int64 { return m.hits.Load() }

// Misses returns the cumulative count of cache misses (org never seen; DB load triggered).
func (m *CacheMetrics) Misses() int64 { return m.misses.Load() }

// ReloadErrors returns the cumulative count of failed DB loads (cache miss or TTL expiry).
func (m *CacheMetrics) ReloadErrors() int64 { return m.reloadErrors.Load() }

// Stale returns the cumulative count of TTL-expired cache entries that triggered a DB reload.
func (m *CacheMetrics) Stale() int64 { return m.stale.Load() }

// Invalidations returns the cumulative count of explicit distributed invalidations.
func (m *CacheMetrics) Invalidations() int64 { return m.invalidations.Load() }

// InvalidationPublishErrors returns the cumulative count of failed invalidation publishes.
func (m *CacheMetrics) InvalidationPublishErrors() int64 {
	return m.invalidationPublishErrors.Load()
}

// InvalidationPublisher publishes cache invalidation events to other replicas.
//
// Implementations should be best-effort: CachingRepository.Upsert has already
// persisted the policy before this is called. Publish failures are surfaced via
// metrics/logs, while TTL remains the fallback convergence mechanism.
type InvalidationPublisher interface {
	PublishGovernanceInvalidation(ctx context.Context, orgID, policyID string) error
}

// CachingRepository wraps a Repository with a per-org in-process policy cache.
//
// Hot path (Evaluate): GetActive returns the cached snapshot if present and
// not stale, making governance enforcement DB-free on the common path.
//
// Write path (Upsert): writes through to the DB and immediately updates the
// cache entry so subsequent Evaluate calls in the same process see the new
// policy without waiting for TTL expiry.
//
// Fail-closed: a DB error on cache miss or stale reload is propagated as-is.
// Service.Evaluate maps it to DecisionDeny/CodePolicyReadFailure. The cache
// entry is NOT updated on error; the next request will retry the DB load.
//
// Org isolation: the cache is keyed by orgID. A miss or error on org A has no
// effect on org B's entry.
type CachingRepository struct {
	inner     Repository
	ttl       time.Duration
	mu        sync.RWMutex
	entries   map[string]*cacheEntry
	metrics   CacheMetrics
	publisher InvalidationPublisher
}

// CacheOption modifies a CachingRepository at construction time.
type CacheOption func(*CachingRepository)

// WithTTL overrides the default policy snapshot TTL (default: 60s).
// A shorter TTL reduces the stale window in multi-replica deployments;
// a longer TTL reduces DB load.
func WithTTL(d time.Duration) CacheOption {
	return func(c *CachingRepository) { c.ttl = d }
}

// WithInvalidationPublisher configures distributed cache invalidation.
// Same-process Upsert remains write-through; the publisher notifies other
// replicas so they drop stale snapshots before TTL expiry.
func WithInvalidationPublisher(p InvalidationPublisher) CacheOption {
	return func(c *CachingRepository) { c.publisher = p }
}

// NewCachingRepository wraps inner with an in-process per-org policy cache.
// Callers in enterprise_wire.go should pass the PGRepository as inner.
func NewCachingRepository(inner Repository, opts ...CacheOption) *CachingRepository {
	c := &CachingRepository{
		inner:   inner,
		ttl:     defaultCacheTTL,
		entries: make(map[string]*cacheEntry),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Metrics returns the per-instance atomic counters for testing assertions.
func (c *CachingRepository) Metrics() *CacheMetrics { return &c.metrics }

// GetActive returns the active policy for orgID.
//
// Decision path:
//  1. Cache entry present and not stale → cache hit, return stored policy.
//  2. Cache entry present but TTL-expired → stale; reload from DB.
//  3. Cache entry absent → miss; load from DB.
//  4. DB error during load → fail-closed (return nil, err); entry NOT updated.
func (c *CachingRepository) GetActive(ctx context.Context, orgID string) (*Policy, error) {
	now := time.Now()

	// Fast path: read lock, check for a fresh entry.
	c.mu.RLock()
	entry := c.entries[orgID]
	c.mu.RUnlock()

	if entry != nil && now.Sub(entry.loadedAt) < c.ttl {
		c.metrics.hits.Add(1)
		govCacheHitsTotal.Inc()
		return entry.policy, nil
	}

	// Classify miss vs stale for metrics.
	if entry != nil {
		c.metrics.stale.Add(1)
		govCacheStaleTotal.Inc()
	} else {
		c.metrics.misses.Add(1)
		govCacheMissesTotal.Inc()
	}

	// Slow path: load from DB.
	policy, err := c.inner.GetActive(ctx, orgID)
	if err != nil {
		c.metrics.reloadErrors.Add(1)
		govCacheReloadErrorsTotal.Inc()
		// Entry NOT updated: next request retries the DB load.
		return nil, err
	}

	// Write-lock only for the map update; DB call above was lock-free.
	// A concurrent goroutine may have also loaded for the same org; the last
	// write wins, which is fine — both loaded the same policy from DB.
	c.mu.Lock()
	c.entries[orgID] = &cacheEntry{policy: policy, loadedAt: time.Now()}
	c.mu.Unlock()

	return policy, nil
}

// Upsert writes through to the DB and atomically updates the cache entry so
// the new policy is visible to all subsequent Evaluate calls in the same
// process without TTL delay.
func (c *CachingRepository) Upsert(ctx context.Context, p *Policy, actor, orgID string) (*Policy, error) {
	saved, err := c.inner.Upsert(ctx, p, actor, orgID)
	if err != nil {
		return nil, err
	}
	// saved is a fresh canonical copy from the DB and is never mutated after
	// this point. Storing it in the cache is safe for concurrent readers.
	c.mu.Lock()
	c.entries[orgID] = &cacheEntry{policy: saved, loadedAt: time.Now()}
	c.mu.Unlock()
	if c.publisher != nil {
		if err := c.publisher.PublishGovernanceInvalidation(ctx, orgID, saved.ID); err != nil {
			c.metrics.invalidationPublishErrors.Add(1)
			govCacheInvalidationPublishErrorsTotal.Inc()
			log.Printf("governance cache: failed to publish invalidation for org=%s policy=%s: %v",
				orgID, saved.ID, err)
		}
	}
	return saved, nil
}

// Invalidate drops a cached policy snapshot for orgID. The next GetActive call
// reloads from DB immediately, regardless of TTL. Empty orgID is ignored to
// avoid accidentally invalidating global/break-glass legacy lookups.
func (c *CachingRepository) Invalidate(orgID string) {
	if orgID == "" {
		return
	}
	c.mu.Lock()
	if _, ok := c.entries[orgID]; ok {
		delete(c.entries, orgID)
		c.metrics.invalidations.Add(1)
		govCacheInvalidationsTotal.Inc()
	}
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Prometheus counters — registered once per process via init().
// Tests read per-instance atomic counters (CacheMetrics) directly to avoid
// Prometheus dependency and cross-test accumulation.
// ---------------------------------------------------------------------------

var (
	govCacheHitsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shadowai_governance_cache_hits_total",
		Help: "Governance policy cache hits: valid snapshot returned without a DB read.",
	})
	govCacheMissesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shadowai_governance_cache_misses_total",
		Help: "Governance policy cache misses: org seen for the first time, DB load triggered.",
	})
	govCacheStaleTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shadowai_governance_cache_stale_total",
		Help: "Governance policy cache stale entries: TTL expired, DB reload triggered.",
	})
	govCacheReloadErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shadowai_governance_cache_reload_errors_total",
		Help: "Governance policy cache reload errors: DB error during cache miss or stale reload.",
	})
	govCacheInvalidationsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shadowai_governance_cache_invalidations_total",
		Help: "Governance policy cache entries invalidated by distributed invalidation events.",
	})
	govCacheInvalidationPublishErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shadowai_governance_cache_invalidation_publish_errors_total",
		Help: "Governance policy cache invalidation publish failures.",
	})
)

func init() {
	prometheus.MustRegister(
		govCacheHitsTotal,
		govCacheMissesTotal,
		govCacheStaleTotal,
		govCacheReloadErrorsTotal,
		govCacheInvalidationsTotal,
		govCacheInvalidationPublishErrorsTotal,
	)
}

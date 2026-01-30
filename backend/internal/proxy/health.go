package proxy

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	healthKeyTTL       = 10 * time.Minute
	latencyListMaxLen  = 100
	healthKeyPrefix    = "health:"
)

// ProviderHealth holds health metrics for a single provider.
type ProviderHealth struct {
	SuccessCount int64
	FailCount    int64
	SuccessRate  float64
	AvgLatencyMs float64
}

// RedisClient is the subset of redis.Client methods used by HealthTracker.
type RedisClient interface {
	Incr(ctx context.Context, key string) *redis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
	Get(ctx context.Context, key string) *redis.StringCmd
	LPush(ctx context.Context, key string, values ...interface{}) *redis.IntCmd
	LTrim(ctx context.Context, key string, start, stop int64) *redis.StatusCmd
	LRange(ctx context.Context, key string, start, stop int64) *redis.StringSliceCmd
}

// HealthTracker records provider success/failure/latency metrics in Redis.
type HealthTracker struct {
	redis RedisClient
}

// NewHealthTracker creates a new HealthTracker.
func NewHealthTracker(rc RedisClient) *HealthTracker {
	return &HealthTracker{redis: rc}
}

func successKey(provider string) string {
	return fmt.Sprintf("%s%s:success", healthKeyPrefix, provider)
}
func failKey(provider string) string {
	return fmt.Sprintf("%s%s:fail", healthKeyPrefix, provider)
}
func latencyKey(provider string) string {
	return fmt.Sprintf("%s%s:latency", healthKeyPrefix, provider)
}

// RecordSuccess increments the success counter and records latency.
func (h *HealthTracker) RecordSuccess(ctx context.Context, provider string, latencyMs int64) {
	sk := successKey(provider)
	h.redis.Incr(ctx, sk)
	h.redis.Expire(ctx, sk, healthKeyTTL)

	lk := latencyKey(provider)
	h.redis.LPush(ctx, lk, latencyMs)
	h.redis.LTrim(ctx, lk, 0, latencyListMaxLen-1)
	h.redis.Expire(ctx, lk, healthKeyTTL)
}

// RecordFailure increments the failure counter.
func (h *HealthTracker) RecordFailure(ctx context.Context, provider string) {
	fk := failKey(provider)
	h.redis.Incr(ctx, fk)
	h.redis.Expire(ctx, fk, healthKeyTTL)
}

// GetHealth returns health metrics for a single provider.
func (h *HealthTracker) GetHealth(ctx context.Context, provider string) *ProviderHealth {
	succStr, _ := h.redis.Get(ctx, successKey(provider)).Result()
	failStr, _ := h.redis.Get(ctx, failKey(provider)).Result()

	succ, _ := strconv.ParseInt(succStr, 10, 64)
	fail, _ := strconv.ParseInt(failStr, 10, 64)

	total := succ + fail
	var rate float64
	if total > 0 {
		rate = float64(succ) / float64(total)
	}

	vals, _ := h.redis.LRange(ctx, latencyKey(provider), 0, -1).Result()
	var avgLatency float64
	if len(vals) > 0 {
		var sum int64
		for _, v := range vals {
			n, _ := strconv.ParseInt(v, 10, 64)
			sum += n
		}
		avgLatency = float64(sum) / float64(len(vals))
	}

	return &ProviderHealth{
		SuccessCount: succ,
		FailCount:    fail,
		SuccessRate:  rate,
		AvgLatencyMs: avgLatency,
	}
}

// GetAllHealth returns health metrics for all providers in the list.
func (h *HealthTracker) GetAllHealth(ctx context.Context, providers []string) map[string]*ProviderHealth {
	result := make(map[string]*ProviderHealth, len(providers))
	for _, p := range providers {
		result[p] = h.GetHealth(ctx, p)
	}
	return result
}

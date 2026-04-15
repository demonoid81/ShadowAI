package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	cachePrefix    = "cache:"
	cacheHitKey    = "cache:stats:hits"
	cacheMissKey   = "cache:stats:misses"
)

// CacheEntry represents a cached response.
type CacheEntry struct {
	StatusCode   int               `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	Body         []byte            `json:"body"`
	Provider     string            `json:"provider"`
	Model        string            `json:"model"`
	CachedAt     time.Time         `json:"cached_at"`
}

// SemanticCache provides exact-match caching for AI responses in Redis.
type SemanticCache struct {
	redis RedisClient
	ttl   time.Duration
}

// NewSemanticCache creates a new SemanticCache. Returns nil if ttl is 0.
func NewSemanticCache(rc RedisClient, ttl time.Duration) *SemanticCache {
	if ttl == 0 {
		return nil
	}
	return &SemanticCache{redis: rc, ttl: ttl}
}

// CacheKey computes a SHA256 hash key from provider, model, and messages JSON.
func CacheKey(provider, model string, messagesJSON []byte) string {
	return CacheKeyForUser("", provider, model, messagesJSON)
}

// CacheKeyForUser computes a SHA256 hash key from user, provider, model, and messages JSON.
func CacheKeyForUser(userID, provider, model string, messagesJSON []byte) string {
	h := sha256.New()
	if userID != "" {
		h.Write([]byte("user:"))
		h.Write([]byte(userID))
		h.Write([]byte("|"))
	}
	h.Write([]byte(provider))
	h.Write([]byte("|"))
	h.Write([]byte(model))
	h.Write([]byte("|"))
	h.Write(messagesJSON)
	return fmt.Sprintf("%s%x", cachePrefix, h.Sum(nil))
}

// Get retrieves a cached entry by key.
func (c *SemanticCache) Get(ctx context.Context, key string) (*CacheEntry, error) {
	data, err := c.redis.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entry CacheEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// Set stores a response in the cache.
func (c *SemanticCache) Set(ctx context.Context, key string, entry *CacheEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return c.redis.Set(ctx, key, data, c.ttl).Err()
}

// ShouldCache returns true if the response should be cached.
func ShouldCache(statusCode int, isStreaming bool, noCache bool) bool {
	if noCache || isStreaming {
		return false
	}
	return statusCode >= 200 && statusCode < 300
}

// IncrHit increments the cache hit counter.
func (c *SemanticCache) IncrHit(ctx context.Context) {
	c.redis.Incr(ctx, cacheHitKey)
}

// IncrMiss increments the cache miss counter.
func (c *SemanticCache) IncrMiss(ctx context.Context) {
	c.redis.Incr(ctx, cacheMissKey)
}

package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/shadowai/backend/internal/auth"
)

func RateLimit(rdb *redis.Client, limit int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.GetClaims(r.Context())
			if claims == nil {
				next.ServeHTTP(w, r)
				return
			}

			key := fmt.Sprintf("ratelimit:%s", claims.UserID)
			ctx := r.Context()
			now := time.Now().UnixNano()

			pipe := rdb.Pipeline()
			pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", now-window.Nanoseconds()))
			pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: now})
			pipe.ZCard(ctx, key)
			pipe.Expire(ctx, key, window)
			results, err := pipe.Exec(ctx)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			count := results[2].(*redis.IntCmd).Val()
			if count > int64(limit) {
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

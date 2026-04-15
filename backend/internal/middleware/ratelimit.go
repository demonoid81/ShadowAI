package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/shadowai/backend/internal/auth"
)

var trustedProxyNets []*net.IPNet

func RateLimit(rdb *redis.Client, limit int, window time.Duration) func(http.Handler) http.Handler {
	return RateLimitWithKeyFunc(rdb, limit, window, func(r *http.Request) (string, bool) {
		claims := auth.GetClaims(r.Context())
		if claims == nil || claims.UserID == "" {
			return "", false
		}
		return fmt.Sprintf("ratelimit:user:%s", claims.UserID), true
	})
}

// RateLimitPublic enforces limits by source IP for public endpoints (e.g. login/register).
func RateLimitPublic(rdb *redis.Client, limit int, window time.Duration) func(http.Handler) http.Handler {
	return RateLimitWithKeyFunc(rdb, limit, window, func(r *http.Request) (string, bool) {
		ip := ClientIP(r)
		if ip == "" {
			return "", false
		}
		return fmt.Sprintf("ratelimit:ip:%s", ip), true
	})
}

func RateLimitWithKeyFunc(rdb *redis.Client, limit int, window time.Duration, keyFn func(*http.Request) (string, bool)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, ok := keyFn(r)
			if !ok || key == "" {
				next.ServeHTTP(w, r)
				return
			}

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
			if len(results) < 3 {
				next.ServeHTTP(w, r)
				return
			}
			intCmd, ok := results[2].(*redis.IntCmd)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			count := intCmd.Val()
			if count > int64(limit) {
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ConfigureTrustedProxies sets which proxy source IP ranges are allowed to pass client IP headers.
func ConfigureTrustedProxies(cidrList string) {
	if strings.TrimSpace(cidrList) == "" {
		trustedProxyNets = nil
		return
	}
	parts := strings.Split(cidrList, ",")
	parsed := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		cidr := strings.TrimSpace(part)
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		parsed = append(parsed, ipNet)
	}
	trustedProxyNets = parsed
}

// ClientIP extracts best-effort real client IP from reverse-proxy headers.
func ClientIP(r *http.Request) string {
	remoteAddrIP := parseIPFromHost(r.RemoteAddr)
	if remoteAddrIP == nil {
		return ""
	}
	if isTrustedProxy(remoteAddrIP) {
		if ip := parseIPFromHeader(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
		if ip := parseIPFromHeader(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
	}
	return remoteAddrIP.String()
}

func isTrustedProxy(ip net.IP) bool {
	if len(trustedProxyNets) == 0 {
		return false
	}
	for _, network := range trustedProxyNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseIPFromHost(hostport string) net.IP {
	if hostport == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return nil
	}
	return ip
}

func parseIPFromHeader(header string) string {
	for _, value := range strings.Split(header, ",") {
		candidate := strings.TrimSpace(value)
		if candidate == "" {
			continue
		}
		if net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	return ""
}

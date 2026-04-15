package middleware

import (
	"net/http"
	"time"
)

// SecurityHeaders sets common hardened response headers.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		if _, ok := w.Header()["Content-Security-Policy"]; !ok {
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
		}

		next.ServeHTTP(w, r)
	})
}

// APIServerTimeouts returns defaults suitable for API workloads.
func APIServerTimeouts() (read, write, idle, readHeader time.Duration) {
	return 15 * time.Second, 120 * time.Second, 120 * time.Second, 5 * time.Second
}

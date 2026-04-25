//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// PR-E1.1: Break-glass emergency admin access.
//
// When OIDC is the primary auth path, break-glass provides a password-based
// emergency admin login with:
//   - Rate limiting (3 attempts / 15 min globally, per-IP)
//   - Short-lived JWT (BREAK_GLASS_JWT_TTL, default 1h)
//   - All attempts audited (success + failure, with IP + timestamp)
//   - BreakGlass=true claim in JWT (visible to governance/audit middleware)
package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/shadowai/backend/internal/domain"
)

const (
	breakGlassRateLimitWindow = 15 * time.Minute
	breakGlassMaxAttempts     = 3
)

// BreakGlassRateLimiter is a simple in-process rate limiter for break-glass attempts.
// In multi-instance deploys this should be backed by Redis; for now it's per-instance.
// (Multi-instance: each instance allows 3 attempts independently — acceptable since
// break-glass is only used during major outages when pod coordination may be degraded.)
type BreakGlassRateLimiter struct {
	attempts  int
	resetAt   time.Time
}

// Allow returns true if an attempt is permitted.
func (r *BreakGlassRateLimiter) Allow() bool {
	now := time.Now()
	if now.After(r.resetAt) {
		r.attempts = 0
		r.resetAt = now.Add(breakGlassRateLimitWindow)
	}
	if r.attempts >= breakGlassMaxAttempts {
		return false
	}
	r.attempts++
	return true
}

// BreakGlassLogin authenticates against the break-glass secret and issues a
// short-lived JWT with BreakGlass=true claim.
//
// secretHash — bcrypt hash of the break-glass password (from BREAK_GLASS_SECRET_HASH).
// jwtTTL     — JWT lifetime (BREAK_GLASS_JWT_TTL, default 1h).
func (s *Service) BreakGlassLogin(ctx context.Context, secret, secretHash string, jwtTTL time.Duration) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("break_glass: secret required")
	}
	if secretHash == "" {
		return "", fmt.Errorf("break_glass: not configured (BREAK_GLASS_SECRET_HASH not set)")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(secret)); err != nil {
		return "", fmt.Errorf("break_glass: invalid secret")
	}
	return s.issueBreakGlassToken(jwtTTL)
}

func (s *Service) issueBreakGlassToken(ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = time.Hour
	}
	claims := &Claims{
		UserID:     "break-glass",
		Email:      "break-glass@system",
		Role:       RoleAdmin,
		BreakGlass: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// BreakGlassUser is a synthetic domain.User for break-glass sessions.
// It has admin role but no DB record — use only for audit metadata.
func BreakGlassUser() *domain.User {
	id := "break-glass"
	email := "break-glass@system"
	return &domain.User{
		ID:    id,
		Email: email,
		Role:  RoleAdmin,
	}
}

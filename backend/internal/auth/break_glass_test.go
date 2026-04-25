//go:build enterprise

package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func hashSecret(t *testing.T, s string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

// TestBreakGlass_ValidSecret_IssuesToken.
func TestBreakGlass_ValidSecret_IssuesToken(t *testing.T) {
	svc := &Service{jwtSecret: []byte("test-secret-for-break-glass!!!!")}
	hash := hashSecret(t, "emergency-password-123")

	token, err := svc.BreakGlassLogin(context.Background(), "emergency-password-123", hash, time.Hour)
	if err != nil {
		t.Fatalf("BreakGlassLogin: %v", err)
	}
	if token == "" {
		t.Error("break-glass token must not be empty")
	}
}

// TestBreakGlass_WrongSecret_Rejected.
func TestBreakGlass_WrongSecret_Rejected(t *testing.T) {
	svc := &Service{jwtSecret: []byte("test-secret-for-break-glass!!!!")}
	hash := hashSecret(t, "correct-password-123")

	_, err := svc.BreakGlassLogin(context.Background(), "wrong-password", hash, time.Hour)
	if err == nil {
		t.Error("wrong secret: expected error, got nil")
	}
}

// TestBreakGlass_EmptyHash_Rejected — not configured → reject.
func TestBreakGlass_EmptyHash_Rejected(t *testing.T) {
	svc := &Service{jwtSecret: []byte("test-secret-for-break-glass!!!!")}
	_, err := svc.BreakGlassLogin(context.Background(), "any-secret", "", time.Hour)
	if err == nil {
		t.Error("empty hash: expected error, got nil")
	}
}

// TestBreakGlass_EmptySecret_Rejected.
func TestBreakGlass_EmptySecret_Rejected(t *testing.T) {
	svc := &Service{jwtSecret: []byte("test-secret-for-break-glass!!!!")}
	_, err := svc.BreakGlassLogin(context.Background(), "", "some-hash", time.Hour)
	if err == nil {
		t.Error("empty secret: expected error, got nil")
	}
}

// TestBreakGlass_TokenHasBreakGlassClaim — issued JWT must have BreakGlass=true.
func TestBreakGlass_TokenHasBreakGlassClaim(t *testing.T) {
	svc := &Service{jwtSecret: []byte("test-secret-for-break-glass!!!!")}
	hash := hashSecret(t, "emergency-pwd")
	token, _ := svc.BreakGlassLogin(context.Background(), "emergency-pwd", hash, time.Hour)

	// Parse and check claims without full validation (we trust our own secret).
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("not a valid JWT format")
	}
	claims, err := svc.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if !claims.BreakGlass {
		t.Error("break-glass JWT must have BreakGlass=true claim")
	}
	if claims.Role != RoleAdmin {
		t.Errorf("role = %q, want admin", claims.Role)
	}
}

// TestBreakGlass_RateLimiter_BlocksAfterMaxAttempts.
func TestBreakGlass_RateLimiter_BlocksAfterMaxAttempts(t *testing.T) {
	rl := &BreakGlassRateLimiter{}
	for i := 0; i < breakGlassMaxAttempts; i++ {
		if !rl.Allow() {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	if rl.Allow() {
		t.Error("attempt after max should be denied")
	}
}

// TestBreakGlass_RateLimiter_ResetsAfterWindow.
func TestBreakGlass_RateLimiter_ResetsAfterWindow(t *testing.T) {
	rl := &BreakGlassRateLimiter{}
	for i := 0; i < breakGlassMaxAttempts; i++ {
		rl.Allow()
	}
	// Manually expire the window.
	rl.resetAt = time.Now().Add(-time.Second)
	if !rl.Allow() {
		t.Error("after window reset, attempt should be allowed")
	}
}

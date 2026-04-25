//go:build enterprise

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// TestBreakGlass_TokenPassesAuthMiddleware — break-glass JWT must pass AuthMiddleware
// and RequireRole(admin) without a DB user record.
// Regression for High finding: UserID="break-glass" has no DB row.
func TestBreakGlass_TokenPassesAuthMiddleware(t *testing.T) {
	svc := &Service{jwtSecret: []byte("test-secret-for-break-glass!!!!")}

	// Issue a break-glass token.
	hash := hashSecret(t, "bg-password-123")
	bgToken, err := svc.BreakGlassLogin(context.Background(), "bg-password-123", hash, time.Hour)
	if err != nil {
		t.Fatalf("BreakGlassLogin: %v", err)
	}

	// AuthMiddleware with a nil repository (break-glass must NOT call GetByID).
	svcNilRepo := &Service{jwtSecret: svc.jwtSecret, repo: nil}
	var capturedClaims *Claims
	handler := svcNilRepo.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedClaims = GetClaims(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+bgToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("break-glass: AuthMiddleware returned %d, want 200 (must not call GetByID)", rr.Code)
	}
	if capturedClaims == nil {
		t.Fatal("capturedClaims is nil — middleware did not set claims")
	}
	if !capturedClaims.BreakGlass {
		t.Error("BreakGlass claim must be true")
	}
	if capturedClaims.Role != RoleAdmin {
		t.Errorf("Role = %q, want admin", capturedClaims.Role)
	}
}

// TestBreakGlass_TokenPassesRequireRole — break-glass JWT must satisfy RequireRole(admin).
func TestBreakGlass_TokenPassesRequireRole(t *testing.T) {
	svc := &Service{jwtSecret: []byte("test-secret-for-break-glass!!!!")}
	hash := hashSecret(t, "bg-password-456")
	bgToken, _ := svc.BreakGlassLogin(context.Background(), "bg-password-456", hash, time.Hour)

	svcNilRepo := &Service{jwtSecret: svc.jwtSecret, repo: nil}
	adminHandler := RequireRole(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler := svcNilRepo.AuthMiddleware(adminHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/test", nil)
	req.Header.Set("Authorization", "Bearer "+bgToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("break-glass + RequireRole(admin): got %d, want 200", rr.Code)
	}
}

// TestIsMFAEnrollmentPath — enrollment exception path matching.
// Ensures that only setup/confirm bypass adminMFARequired block.
func TestIsMFAEnrollmentPath(t *testing.T) {
	allowed := []string{
		"/api/auth/mfa/setup",
		"/api/auth/mfa/confirm",
	}
	blocked := []string{
		"/api/users",
		"/api/admin-events",
		"/api/auth/mfa/verify",  // verify is a public route, not enrollment
		"/api/auth/mfa",         // disable — not enrollment
		"/api/governance/policy",
	}
	for _, p := range allowed {
		if !isMFAEnrollmentPath(p) {
			t.Errorf("isMFAEnrollmentPath(%q) = false, want true (enrollment exception)", p)
		}
	}
	for _, p := range blocked {
		if isMFAEnrollmentPath(p) {
			t.Errorf("isMFAEnrollmentPath(%q) = true, want false (should be blocked)", p)
		}
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

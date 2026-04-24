package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

// okHandler is a simple handler that writes 200 OK.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
})

func ctxWithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}

func TestGetClaims_NoClaims(t *testing.T) {
	ctx := context.Background()
	claims := GetClaims(ctx)
	if claims != nil {
		t.Fatalf("expected nil claims, got %+v", claims)
	}
}

func TestGetClaims_WithClaims(t *testing.T) {
	expected := &Claims{
		UserID: "user-1",
		Email:  "test@example.com",
		Role:   "user",
	}
	ctx := ctxWithClaims(context.Background(), expected)
	claims := GetClaims(ctx)
	if claims == nil {
		t.Fatal("expected claims, got nil")
	}
	if claims.UserID != expected.UserID {
		t.Fatalf("expected UserID %q, got %q", expected.UserID, claims.UserID)
	}
	if claims.Email != expected.Email {
		t.Fatalf("expected Email %q, got %q", expected.Email, claims.Email)
	}
	if claims.Role != expected.Role {
		t.Fatalf("expected Role %q, got %q", expected.Role, claims.Role)
	}
}

func TestRequireRole_NoClaims(t *testing.T) {
	middleware := RequireRole("admin")
	handler := middleware(okHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestRequireRole_WrongRole(t *testing.T) {
	middleware := RequireRole("admin")
	handler := middleware(okHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctxWithClaims(req.Context(), &Claims{
		UserID: "user-1",
		Role:   "user",
	}))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}

func TestRequireRole_MatchingRole(t *testing.T) {
	middleware := RequireRole("admin")
	handler := middleware(okHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctxWithClaims(req.Context(), &Claims{
		UserID: "user-1",
		Role:   "admin",
	}))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestRequireRole_MultipleRolesOneMatches(t *testing.T) {
	middleware := RequireRole("admin", "editor", "viewer")
	handler := middleware(okHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctxWithClaims(req.Context(), &Claims{
		UserID: "user-1",
		Role:   "editor",
	}))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestRequireAdminOrSelf_AdminAlwaysPasses(t *testing.T) {
	middleware := RequireAdminOrSelf("id")
	handler := middleware(okHandler)

	req := httptest.NewRequest(http.MethodGet, "/users/other-user", nil)
	req = req.WithContext(ctxWithClaims(req.Context(), &Claims{
		UserID: "admin-1",
		Role:   "admin",
	}))
	// Admin should pass even without matching path param
	req = mux.SetURLVars(req, map[string]string{"id": "other-user"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestRequireAdminOrSelf_UserMatchingID(t *testing.T) {
	middleware := RequireAdminOrSelf("id")
	handler := middleware(okHandler)

	req := httptest.NewRequest(http.MethodGet, "/users/user-123", nil)
	req = req.WithContext(ctxWithClaims(req.Context(), &Claims{
		UserID: "user-123",
		Role:   "user",
	}))
	req = mux.SetURLVars(req, map[string]string{"id": "user-123"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestRequireAdminOrSelf_UserDifferentID(t *testing.T) {
	middleware := RequireAdminOrSelf("id")
	handler := middleware(okHandler)

	req := httptest.NewRequest(http.MethodGet, "/users/other-user", nil)
	req = req.WithContext(ctxWithClaims(req.Context(), &Claims{
		UserID: "user-123",
		Role:   "user",
	}))
	req = mux.SetURLVars(req, map[string]string{"id": "other-user"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}

func TestRequireAdminOrSelf_NoClaims(t *testing.T) {
	middleware := RequireAdminOrSelf("id")
	handler := middleware(okHandler)

	req := httptest.NewRequest(http.MethodGet, "/users/user-123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "user-123"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// ---------------------------------------------------------------------------
// PR-G3: ptrStr helper
// ---------------------------------------------------------------------------

func TestPtrStr_Nil(t *testing.T) {
	if got := ptrStr(nil); got != "" {
		t.Errorf("ptrStr(nil) = %q, want empty string", got)
	}
}

func TestPtrStr_Value(t *testing.T) {
	s := "finance"
	if got := ptrStr(&s); got != "finance" {
		t.Errorf("ptrStr(&%q) = %q, want finance", s, got)
	}
}

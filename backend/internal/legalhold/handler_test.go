//go:build enterprise

package legalhold

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/auth"
)

type captureRecorder struct {
	events []adminaudit.Event
}

func (c *captureRecorder) Record(_ context.Context, ev adminaudit.Event) {
	c.events = append(c.events, ev)
}

func setupHandler(t *testing.T) (*Handler, *memRepo, *captureRecorder) {
	t.Helper()
	repo := &memRepo{}
	rec := &captureRecorder{}
	return NewHandler(NewService(repo), rec), repo, rec
}

func adminCtx(req *http.Request, actor string) *http.Request {
	return req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: actor, Role: auth.RoleAdmin,
	}))
}

// TestCreate_HappyPath — admin создаёт hold; event recorded.
func TestCreate_HappyPath(t *testing.T) {
	h, repo, rec := setupHandler(t)
	body := `{"target_user_id":"u-target","case_ref":"case-42","reason":"litigation"}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin")
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if len(repo.holds) != 1 || !repo.holds[0].IsActive {
		t.Errorf("repo state = %+v", repo.holds)
	}
	if len(rec.events) != 1 || rec.events[0].Action != "apply_hold" {
		t.Errorf("events = %+v", rec.events)
	}
	if !rec.events[0].Success {
		t.Error("admin event success=false на happy path")
	}
}

// TestCreate_NonAdmin_Forbidden.
func TestCreate_NonAdmin(t *testing.T) {
	h, _, _ := setupHandler(t)
	body := `{"target_user_id":"u-target","case_ref":"x","reason":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body))
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-1", Role: auth.RoleUser,
	}))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// TestCreate_Unauthenticated.
func TestCreate_Unauthenticated(t *testing.T) {
	h, _, _ := setupHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// TestCreate_Duplicate_409.
func TestCreate_Duplicate(t *testing.T) {
	h, _, rec := setupHandler(t)
	body := `{"target_user_id":"u-1","case_ref":"c1","reason":"r"}`
	w1 := httptest.NewRecorder()
	h.Create(w1, adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin"))
	if w1.Code != http.StatusCreated {
		t.Fatalf("first create status = %d", w1.Code)
	}
	w2 := httptest.NewRecorder()
	h.Create(w2, adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin"))
	if w2.Code != http.StatusConflict {
		t.Errorf("second create status = %d, want 409", w2.Code)
	}
	// 2 events: первый success, второй failure с already_active.
	if len(rec.events) != 2 {
		t.Fatalf("events = %d, want 2", len(rec.events))
	}
	if rec.events[1].Success {
		t.Error("second event success=true, expected false")
	}
}

// TestCreate_ValidationError_400.
func TestCreate_ValidationError(t *testing.T) {
	h, _, _ := setupHandler(t)
	body := `{"target_user_id":"","case_ref":"","reason":""}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin")
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// TestRelease_HappyPath.
func TestRelease_HappyPath(t *testing.T) {
	h, repo, rec := setupHandler(t)
	// Seed через service → repo (сохранение нормального flow).
	ctx := context.Background()
	seeded, _ := h.svc.CreateHold(ctx, "u-1", "c1", "r", "u-admin")

	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/release", nil), "u-admin")
	req = mux.SetURLVars(req, map[string]string{"id": seeded.ID})
	w := httptest.NewRecorder()
	h.Release(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if repo.holds[0].IsActive {
		t.Error("hold still active after release")
	}
	// Seed был через svc.CreateHold (bypass handler), поэтому в rec
	// только release_hold. Проверяем это явно.
	actions := actionsFromEvents(rec.events)
	if len(actions) != 1 || actions[0] != "release_hold" {
		t.Errorf("actions = %v, want [release_hold]", actions)
	}
}

// TestRelease_Idempotent — second release возвращает 200 со
// status=already_released.
func TestRelease_Idempotent(t *testing.T) {
	h, _, _ := setupHandler(t)
	ctx := context.Background()
	seeded, _ := h.svc.CreateHold(ctx, "u-1", "c1", "r", "u-admin")
	// First release.
	req1 := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/release", nil), "u-admin")
	req1 = mux.SetURLVars(req1, map[string]string{"id": seeded.ID})
	h.Release(httptest.NewRecorder(), req1)

	// Second release.
	req2 := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/release", nil), "u-admin")
	req2 = mux.SetURLVars(req2, map[string]string{"id": seeded.ID})
	w2 := httptest.NewRecorder()
	h.Release(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("second release status = %d, want 200 (idempotent)", w2.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(w2.Body.Bytes(), &resp)
	if resp["status"] != "already_released" {
		t.Errorf("response = %+v, want status=already_released", resp)
	}
}

// TestRelease_NotFound.
func TestRelease_NotFound(t *testing.T) {
	h, _, _ := setupHandler(t)
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/h-missing/release", nil), "u-admin")
	req = mux.SetURLVars(req, map[string]string{"id": "h-missing"})
	w := httptest.NewRecorder()
	h.Release(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// TestList_HappyPath.
func TestList_HappyPath(t *testing.T) {
	h, _, rec := setupHandler(t)
	ctx := context.Background()
	_, _ = h.svc.CreateHold(ctx, "u-1", "c1", "r", "u-admin")
	_, _ = h.svc.CreateHold(ctx, "u-2", "c2", "r", "u-admin")

	req := adminCtx(httptest.NewRequest(http.MethodGet, "/api/legal-holds", nil), "u-admin")
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var out []holdResponse
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if len(out) != 2 {
		t.Errorf("list len = %d, want 2", len(out))
	}
	// Admin event должен содержать active_count=2.
	meta := rec.events[len(rec.events)-1].Metadata.(map[string]any)
	if meta["active_count"] != 2 {
		t.Errorf("active_count = %v, want 2", meta["active_count"])
	}
}

func actionsFromEvents(events []adminaudit.Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Action)
	}
	return out
}

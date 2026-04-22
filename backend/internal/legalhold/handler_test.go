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

// TestCreate_MetadataHasHashNotRawCaseRef — PR-L1.1 privacy
// regression guard. admin_event metadata должна содержать
// case_ref_hash, а case_ref (raw) должен отсутствовать.
func TestCreate_MetadataHasHashNotRawCaseRef(t *testing.T) {
	h, _, rec := setupHandler(t)
	rawCaseRef := "SEC-INTERNAL-2026-SECRET-42"
	body := `{"target_user_id":"u-1","case_ref":"` + rawCaseRef + `","reason":"r"}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin")
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d", w.Code)
	}
	if len(rec.events) != 1 {
		t.Fatalf("events = %d", len(rec.events))
	}
	meta := rec.events[0].Metadata.(map[string]any)

	// Правильный ключ присутствует.
	hash, ok := meta["case_ref_hash"].(string)
	if !ok || hash == "" {
		t.Errorf("case_ref_hash missing/empty in metadata: %+v", meta)
	}
	// Длина hash = 16 hex chars (truncated SHA-256, 64 bit).
	if len(hash) != 16 {
		t.Errorf("case_ref_hash len = %d, want 16", len(hash))
	}

	// Raw case_ref НЕ должен присутствовать ни под одним ключом.
	for k, v := range meta {
		if s, ok := v.(string); ok && s == rawCaseRef {
			t.Errorf("raw case_ref leak through metadata[%q] = %q", k, s)
		}
	}
	if _, has := meta["case_ref"]; has {
		t.Error("metadata содержит raw 'case_ref' ключ")
	}
}

// TestCreate_ConflictEventHasHashNotRawCaseRef — privacy guard
// для 409 path: conflict event тоже должен содержать hash, не raw.
func TestCreate_ConflictEventHasHashNotRawCaseRef(t *testing.T) {
	h, _, rec := setupHandler(t)
	rawCaseRef := "DOJ-LEAKED-REFERENCE"
	body := `{"target_user_id":"u-1","case_ref":"` + rawCaseRef + `","reason":"r"}`
	// First create succeeds.
	h.Create(httptest.NewRecorder(), adminCtx(
		httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin"))
	// Second → 409 conflict.
	w := httptest.NewRecorder()
	h.Create(w, adminCtx(
		httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin"))

	if w.Code != http.StatusConflict {
		t.Fatalf("second create status = %d, want 409", w.Code)
	}
	if len(rec.events) != 2 {
		t.Fatalf("events = %d", len(rec.events))
	}
	conflictMeta := rec.events[1].Metadata.(map[string]any)
	if conflictMeta["error_code"] != "already_active" {
		t.Errorf("error_code = %v, want already_active", conflictMeta["error_code"])
	}
	if _, has := conflictMeta["case_ref"]; has {
		t.Error("conflict event содержит raw case_ref")
	}
	for k, v := range conflictMeta {
		if s, ok := v.(string); ok && s == rawCaseRef {
			t.Errorf("raw case_ref leak в conflict event metadata[%q]", k)
		}
	}
}

// TestCreate_ValidationError_GenericMessage — PR-L1.1 error split.
// Client не должен получать raw err.Error() с internal path.
func TestCreate_ValidationError_GenericMessage(t *testing.T) {
	h, _, rec := setupHandler(t)
	body := `{"target_user_id":"u-1","case_ref":"","reason":""}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin")
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}

	// Response body не должен содержать "legalhold:" prefix —
	// internal err string не должен leak'аться клиенту.
	bodyStr := w.Body.String()
	if bytes.Contains([]byte(bodyStr), []byte("legalhold:")) {
		t.Errorf("response leaks internal error string: %s", bodyStr)
	}

	// Admin event metadata содержит error_code, не raw message.
	meta := rec.events[0].Metadata.(map[string]any)
	if meta["error_code"] != "validation_failed" {
		t.Errorf("error_code = %v, want validation_failed", meta["error_code"])
	}
	if _, has := meta["error"]; has {
		// Старый shape {"error": "legalhold: ..."} — не должен
		// присутствовать после PR-L1.1.
		t.Error("metadata содержит legacy 'error' key вместо error_code")
	}
}

// TestCreate_NotConfigured_Returns503 — service без repo
// (nil Service.repo) → 503 + error_code=not_configured.
func TestCreate_NotConfigured_Returns503(t *testing.T) {
	rec := &captureRecorder{}
	h := NewHandler(&Service{repo: nil}, rec) // not configured
	body := `{"target_user_id":"u-1","case_ref":"c","reason":"r"}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin")
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if len(rec.events) != 1 {
		t.Fatalf("events = %d", len(rec.events))
	}
	meta := rec.events[0].Metadata.(map[string]any)
	if meta["error_code"] != "not_configured" {
		t.Errorf("error_code = %v, want not_configured", meta["error_code"])
	}
}

// TestRelease_HappyPath_MetadataHasHashOnly — privacy guard для
// release event.
func TestRelease_HappyPath_MetadataHasHashOnly(t *testing.T) {
	h, _, rec := setupHandler(t)
	ctx := context.Background()
	rawCaseRef := "CFPB-PRIVATE-MATTER"
	seeded, _ := h.svc.CreateHold(ctx, "u-1", rawCaseRef, "r", "u-admin")

	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/release", nil), "u-admin")
	req = mux.SetURLVars(req, map[string]string{"id": seeded.ID})
	h.Release(httptest.NewRecorder(), req)

	// seed через svc bypass handler, в rec только release event.
	if len(rec.events) != 1 {
		t.Fatalf("events = %d, want 1", len(rec.events))
	}
	meta := rec.events[0].Metadata.(map[string]any)
	if _, has := meta["case_ref"]; has {
		t.Error("release event содержит raw case_ref")
	}
	hash, _ := meta["case_ref_hash"].(string)
	if hash == "" || len(hash) != 16 {
		t.Errorf("case_ref_hash malformed: %q", hash)
	}
}

// TestCaseRefHash_Deterministic — одинаковый case_ref всегда даёт
// одинаковый hash (SIEM может correlate events).
func TestCaseRefHash_Deterministic(t *testing.T) {
	a := caseRefHash("SEC-2026-042")
	b := caseRefHash("SEC-2026-042")
	if a != b {
		t.Errorf("hash not deterministic: %q vs %q", a, b)
	}
	if a == caseRefHash("SEC-2026-043") {
		t.Error("different case_refs produce same hash")
	}
}

func actionsFromEvents(events []adminaudit.Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Action)
	}
	return out
}

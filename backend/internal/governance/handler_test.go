//go:build enterprise

package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/auth"
)

// captureRecorder — in-memory Recorder для проверки admin-audit
// side-effects в handler-tests.
type captureRecorder struct {
	events []adminaudit.Event
}

func (c *captureRecorder) Record(_ context.Context, ev adminaudit.Event) {
	c.events = append(c.events, ev)
}

func newTestHandler(t *testing.T, initial *Policy) (*Handler, *memRepo, *captureRecorder) {
	t.Helper()
	repo := &memRepo{policy: initial}
	rec := &captureRecorder{}
	return NewHandler(NewService(repo), rec), repo, rec
}

// TestGetPolicy_NoneConfigured — свежий deploy, GetActive возвращает
// (nil, nil). Handler даёт 200 + {"configured":false}, чтобы UI
// корректно отобразил onboarding-state вместо 404 error.
func TestGetPolicy_NoneConfigured(t *testing.T) {
	h, _, rec := newTestHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/governance/policy", nil)
	w := httptest.NewRecorder()
	h.GetPolicy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp emptyPolicyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body unmarshal: %v", err)
	}
	if resp.Configured {
		t.Error("configured = true, want false для empty state")
	}
	if len(rec.events) != 1 || rec.events[0].Action != "read" {
		t.Errorf("admin events = %+v, want 1 read event", rec.events)
	}
}

// TestGetPolicy_ReturnsActive — happy path: active политика есть,
// возвращается с rule-count в metadata.
func TestGetPolicy_ReturnsActive(t *testing.T) {
	h, _, rec := newTestHandler(t, &Policy{
		ID: "p-1", Mode: ModeAllowlistStrict, IsActive: true,
		Rules: []ProviderRule{{Provider: "openai", Models: []string{"gpt-4"}}},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/governance/policy", nil)
	w := httptest.NewRecorder()
	h.GetPolicy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp policyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body unmarshal: %v", err)
	}
	if resp.ID != "p-1" || resp.Mode != ModeAllowlistStrict {
		t.Errorf("resp = %+v, want id=p-1 mode=allowlist_strict", resp)
	}
	if len(resp.Rules) != 1 || resp.Rules[0].Provider != "openai" {
		t.Errorf("rules = %+v", resp.Rules)
	}
	// Privacy guard: metadata должен содержать rule_count, но НЕ
	// сами provider/model имена (те уже в body response).
	if len(rec.events) != 1 {
		t.Fatalf("events count = %d, want 1", len(rec.events))
	}
	meta, _ := rec.events[0].Metadata.(map[string]any)
	if meta["rule_count"] != 1 {
		t.Errorf("rule_count = %v, want 1", meta["rule_count"])
	}
}

// TestUpdatePolicy_RequiresAdmin — non-admin юзер получает 403,
// попытка НЕ изменяет policy в repo.
func TestUpdatePolicy_RequiresAdmin(t *testing.T) {
	h, repo, _ := newTestHandler(t, &Policy{
		ID: "p-1", Mode: ModeDisabled, IsActive: true,
	})
	body := `{"name":"default","mode":"allowlist_strict","rules":[]}`
	req := httptest.NewRequest(http.MethodPut, "/api/governance/policy",
		bytes.NewBufferString(body))
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-1", Role: auth.RoleUser, // не admin
	}))
	w := httptest.NewRecorder()
	h.UpdatePolicy(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if repo.policy.Mode != ModeDisabled {
		t.Errorf("policy changed by non-admin: mode=%v", repo.policy.Mode)
	}
}

// TestUpdatePolicy_Unauthenticated — нет claims в context → 401.
func TestUpdatePolicy_Unauthenticated(t *testing.T) {
	h, _, _ := newTestHandler(t, nil)
	req := httptest.NewRequest(http.MethodPut, "/api/governance/policy",
		bytes.NewBufferString(`{"mode":"disabled","rules":[]}`))
	w := httptest.NewRecorder()
	h.UpdatePolicy(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// TestUpdatePolicy_InvalidMode_Rejected — unknown mode → 400 +
// admin-event с attempted_mode для forensics. После PR-G2
// role_based стал валидным → используем device_scope как unknown.
func TestUpdatePolicy_InvalidMode_Rejected(t *testing.T) {
	h, repo, rec := newTestHandler(t, &Policy{
		ID: "p-1", Mode: ModeDisabled, IsActive: true,
	})
	body := `{"mode":"device_scope","rules":[]}` // не поддержан (G3+)
	req := httptest.NewRequest(http.MethodPut, "/api/governance/policy",
		bytes.NewBufferString(body))
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-admin", Role: auth.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	h.UpdatePolicy(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if repo.policy.Mode == "device_scope" {
		t.Error("invalid mode был сохранён")
	}
	if len(rec.events) == 0 {
		t.Fatal("admin event не записан для rejected update")
	}
	meta := rec.events[0].Metadata.(map[string]any)
	if meta["attempted_mode"] != "device_scope" {
		t.Errorf("attempted_mode = %v, want device_scope", meta["attempted_mode"])
	}
}

// TestUpdatePolicy_HappyPath — admin upsert-ит валидную политику.
// Проверяем: repo updated, 200 response, admin-event с mode.
func TestUpdatePolicy_HappyPath(t *testing.T) {
	h, repo, rec := newTestHandler(t, &Policy{
		ID: "p-1", Mode: ModeDisabled, IsActive: true,
	})
	body := `{"name":"default","mode":"allowlist_strict","rules":[
		{"provider":"openai","models":["gpt-4","gpt-4o-mini"]}
	]}`
	req := httptest.NewRequest(http.MethodPut, "/api/governance/policy",
		bytes.NewBufferString(body))
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-admin", Role: auth.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	h.UpdatePolicy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if repo.policy.Mode != ModeAllowlistStrict {
		t.Errorf("mode not updated: %v", repo.policy.Mode)
	}
	if len(repo.policy.Rules) != 1 || repo.policy.Rules[0].Provider != "openai" {
		t.Errorf("rules not persisted: %+v", repo.policy.Rules)
	}
	if len(rec.events) != 1 || rec.events[0].Action != "update" {
		t.Errorf("admin events = %+v, want 1 update", rec.events)
	}
	if !rec.events[0].Success {
		t.Error("admin event success=false для happy path")
	}
}

// TestUpdatePolicy_BadJSON_Rejected — malformed body → 400, не panic.
func TestUpdatePolicy_BadJSON_Rejected(t *testing.T) {
	h, _, _ := newTestHandler(t, nil)
	req := httptest.NewRequest(http.MethodPut, "/api/governance/policy",
		bytes.NewBufferString(`{"mode":`)) // invalid JSON
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-admin", Role: auth.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	h.UpdatePolicy(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

//go:build enterprise

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shadowai/backend/internal/adminaudit"
)

// TestRecordUsersList_NilRecorder — safety guard: если adminAudit=nil
// (Core build / dev), recordUsersList должен быть no-op и не
// panic'овать. Этот helper вызывается из ListUsers на hot path.
func TestRecordUsersList_NilRecorder(t *testing.T) {
	h := &Handler{} // adminAudit=nil
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	h.recordUsersList(req, http.StatusOK, true, map[string]any{"user_count": 5})
}

// TestRecordUsersList_WritesEvent — happy path: валидный recorder,
// admin claims в context. Event содержит action=list, resource=users
// (plural — важно для отличия от read), actor, success, metadata.
func TestRecordUsersList_WritesEvent(t *testing.T) {
	rec := &captureRecorder{}
	h := &Handler{adminAudit: rec}

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req = req.WithContext(WithClaims(req.Context(), &Claims{
		UserID: "u-admin", Email: "admin@example.com", Role: RoleAdmin,
	}))

	h.recordUsersList(req, http.StatusOK, true, map[string]any{
		"user_count": 3,
	})

	if len(rec.events) != 1 {
		t.Fatalf("captured %d events, want 1", len(rec.events))
	}
	ev := rec.events[0]
	if ev.Action != "list" || ev.Resource != "users" {
		t.Errorf("action/resource = %q/%q, want list/users", ev.Action, ev.Resource)
	}
	if ev.TargetID != "" {
		t.Errorf("target_id = %q, want empty (list-scope не имеет target)", ev.TargetID)
	}
	if ev.ActorUserID == nil || *ev.ActorUserID != "u-admin" {
		t.Errorf("actor = %v, want u-admin", ev.ActorUserID)
	}
	if ev.Method != http.MethodGet || ev.Path != "/api/users" {
		t.Errorf("method/path = %q/%q", ev.Method, ev.Path)
	}
	if !ev.Success || ev.StatusCode != http.StatusOK {
		t.Errorf("success/status = %v/%d", ev.Success, ev.StatusCode)
	}

	// Privacy guard: metadata НЕ должен содержать emails/api-keys —
	// response body уже их имеет, дублировать в admin_event_logs
	// избыточно и увеличивает PII-surface.
	if meta, ok := ev.Metadata.(map[string]any); ok {
		for k := range meta {
			switch k {
			case "emails", "email_list", "api_keys", "passwords":
				t.Errorf("metadata содержит PII-ключ %q — нарушение privacy-контракта", k)
			}
		}
		if meta["user_count"] != 3 {
			t.Errorf("user_count = %v, want 3", meta["user_count"])
		}
	}
}

// TestRecordUsersList_FailureStatus — на failure path (repo error →
// 500) event всё равно записывается с success=false. Это критично
// для forensics: "кто пытался read user list, но получил ошибку".
func TestRecordUsersList_FailureStatus(t *testing.T) {
	rec := &captureRecorder{}
	h := &Handler{adminAudit: rec}

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req = req.WithContext(WithClaims(req.Context(), &Claims{
		UserID: "u-admin", Role: RoleAdmin,
	}))

	h.recordUsersList(req, http.StatusInternalServerError, false, map[string]any{
		"error": "repo_failure",
	})

	if len(rec.events) != 1 {
		t.Fatalf("captured %d events", len(rec.events))
	}
	ev := rec.events[0]
	if ev.Success {
		t.Error("success=true для failure path — ожидается false")
	}
	if ev.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", ev.StatusCode)
	}
}

// TestRecordUsersList_UnauthenticatedActor — если claims отсутствуют
// (edge case: middleware не отработал), actor_user_id = nil.
// Event всё равно пишется — отсутствие actor само по себе
// forensic-сигнал.
func TestRecordUsersList_UnauthenticatedActor(t *testing.T) {
	rec := &captureRecorder{}
	h := &Handler{adminAudit: rec}

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	h.recordUsersList(req, http.StatusForbidden, false, nil)

	if len(rec.events) != 1 {
		t.Fatalf("want 1 event, got %d", len(rec.events))
	}
	if rec.events[0].ActorUserID != nil {
		t.Errorf("actor = %v, want nil для unauthenticated", rec.events[0].ActorUserID)
	}
}

// Stability guard: проверяем, что Event struct доступен из core
// (adminaudit.Event) и может быть использован в test helpers без
// enterprise-зависимостей на тип.
var _ = adminaudit.Event{}

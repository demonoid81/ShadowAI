package auth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shadowai/backend/internal/adminaudit"
)

// TestRecordUserRead_NilRecorder — safety guard: если adminAudit=nil
// (dev/test деплой без audit-trail), recordUserRead должен быть no-op
// и не panic'овать. Этот helper вызывается из GetUser на hot path.
func TestRecordUserRead_NilRecorder(t *testing.T) {
	h := &Handler{} // adminAudit=nil
	req := httptest.NewRequest(http.MethodGet, "/api/users/u-1", nil)
	// Must not panic.
	h.recordUserRead(req, "u-1", http.StatusOK, true, map[string]any{"role": "admin"})
}

// TestRecordUserRead_WritesEvent — при валидном recorder event
// создаётся с правильным shape: actor из claims, target_id, resource,
// action, status, success, metadata.
func TestRecordUserRead_WritesEvent(t *testing.T) {
	rec := &captureRecorder{}
	h := &Handler{adminAudit: rec}

	req := httptest.NewRequest(http.MethodGet, "/api/users/u-target", bytes.NewReader(nil))
	req = req.WithContext(WithClaims(req.Context(), &Claims{
		UserID: "u-admin", Email: "admin@example.com", Role: RoleAdmin,
	}))

	h.recordUserRead(req, "u-target", http.StatusOK, true, map[string]any{
		"target_role": "analyst",
	})

	if len(rec.events) != 1 {
		t.Fatalf("captured %d events, want 1", len(rec.events))
	}
	ev := rec.events[0]
	if ev.Action != "read" || ev.Resource != "user" {
		t.Errorf("action/resource = %q/%q", ev.Action, ev.Resource)
	}
	if ev.TargetID != "u-target" {
		t.Errorf("target_id = %q, want u-target", ev.TargetID)
	}
	if ev.ActorUserID == nil || *ev.ActorUserID != "u-admin" {
		t.Errorf("actor = %v, want u-admin", ev.ActorUserID)
	}
	if ev.Method != http.MethodGet || ev.Path != "/api/users/u-target" {
		t.Errorf("method/path = %q/%q", ev.Method, ev.Path)
	}
	if !ev.Success || ev.StatusCode != http.StatusOK {
		t.Errorf("success/status = %v/%d", ev.Success, ev.StatusCode)
	}

	// Privacy guard: metadata НЕ должен содержать email.
	if meta, ok := ev.Metadata.(map[string]any); ok {
		for k, v := range meta {
			if s, ok := v.(string); ok && s == "admin@example.com" {
				t.Errorf("email попал в metadata: %s=%q", k, s)
			}
		}
	}
}

// TestRecordUserRead_UnauthenticatedActor — если claims нет в context
// (edge case — middleware не отработал), actor_user_id = NULL (nil).
// Event всё равно пишется — отсутствие actor это само по себе
// forensic-сигнал.
func TestRecordUserRead_UnauthenticatedActor(t *testing.T) {
	rec := &captureRecorder{}
	h := &Handler{adminAudit: rec}

	req := httptest.NewRequest(http.MethodGet, "/api/users/u-target", nil)
	// No WithClaims — actor should be nil.

	h.recordUserRead(req, "u-target", http.StatusForbidden, false, nil)

	if len(rec.events) != 1 {
		t.Fatalf("want 1 event even without claims, got %d", len(rec.events))
	}
	if rec.events[0].ActorUserID != nil {
		t.Errorf("actor = %v, want nil для unauthenticated", rec.events[0].ActorUserID)
	}
}

// TestRecordUserRead_EmailNotInMetadata — regression-guard для
// PR-G0 privacy-контракта: даже если caller случайно передаст
// raw email в metadata, adminaudit.Service не должен блокировать
// — это обязанность caller'а не писать PII. Этот тест зафиксирует
// что текущая реализация handler'а НЕ передаёт email в metadata
// (проверено через inspection: только target_role).
func TestRecordUserRead_CurrentMetadataShape(t *testing.T) {
	rec := &captureRecorder{}
	h := &Handler{adminAudit: rec}

	req := httptest.NewRequest(http.MethodGet, "/api/users/u-target", nil)
	req = req.WithContext(WithClaims(req.Context(), &Claims{
		UserID: "u-admin", Role: RoleAdmin,
	}))

	// Симулируем вызов точно как в GetUser success path.
	h.recordUserRead(req, "u-target", http.StatusOK, true, map[string]any{
		"target_role": "admin",
	})

	// adminaudit.Service сериализует metadata в JSON. Проверка на
	// уровне Event — только ключи.
	meta, ok := rec.events[0].Metadata.(map[string]any)
	if !ok {
		t.Fatal("metadata не map")
	}
	if _, hasEmail := meta["email"]; hasEmail {
		t.Error("email ключ появился в metadata — нарушение privacy-контракта")
	}
	if _, hasPassword := meta["password"]; hasPassword {
		t.Error("password ключ в metadata — недопустимо")
	}
	if _, hasAPIKey := meta["api_key"]; hasAPIKey {
		t.Error("api_key ключ в metadata — недопустимо")
	}
	if meta["target_role"] != "admin" {
		t.Errorf("target_role = %v, want admin", meta["target_role"])
	}
}

// unused import guard (adminaudit package может быть unused если
// только helper определён без reference); захватывается в test setup.
var _ = adminaudit.Event{}

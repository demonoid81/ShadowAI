//go:build enterprise

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRecordUserUpdate_NilRecorder — safety guard: Core-build / dev
// без adminAudit не должен panic'овать на UpdateUser.
func TestRecordUserUpdate_NilRecorder(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodPut, "/api/users/u-1", nil)
	h.recordUserUpdate(req, "u-1", http.StatusOK, true, map[string]any{"changed_fields": []string{"role"}})
}

// TestRecordUserUpdate_WritesEvent — happy path: event shape
// (action=update, resource=user singular, target_id, actor),
// metadata shape (changed_fields + old/new для role/is_active).
func TestRecordUserUpdate_WritesEvent(t *testing.T) {
	rec := &captureRecorder{}
	h := &Handler{adminAudit: rec}

	req := httptest.NewRequest(http.MethodPut, "/api/users/u-target", nil)
	req = req.WithContext(WithClaims(req.Context(), &Claims{
		UserID: "u-admin", Role: RoleAdmin,
	}))
	h.recordUserUpdate(req, "u-target", http.StatusOK, true, map[string]any{
		"changed_fields": []string{"role"},
		"old_role":       "user",
		"new_role":       "admin",
	})

	if len(rec.events) != 1 {
		t.Fatalf("events = %d, want 1", len(rec.events))
	}
	ev := rec.events[0]
	if ev.Action != "update" || ev.Resource != "user" {
		t.Errorf("action/resource = %q/%q", ev.Action, ev.Resource)
	}
	if ev.TargetID != "u-target" {
		t.Errorf("target_id = %q", ev.TargetID)
	}
	if ev.ActorUserID == nil || *ev.ActorUserID != "u-admin" {
		t.Errorf("actor = %v", ev.ActorUserID)
	}
	if !ev.Success {
		t.Error("success=false на happy path")
	}

	// Privacy guard: metadata НЕ должен содержать email/password/api_key.
	if meta, ok := ev.Metadata.(map[string]any); ok {
		for _, banned := range []string{"email", "password", "api_key", "new_email", "old_email"} {
			if _, has := meta[banned]; has {
				t.Errorf("metadata содержит PII-ключ %q — нарушение privacy-контракта", banned)
			}
		}
	}
}

// TestRecordUserUpdate_FailurePaths — 404/400/500 тоже пишут event
// с success=false. Это критично для forensics: «кто пытался
// изменить роль, но получил ошибку».
func TestRecordUserUpdate_FailurePaths(t *testing.T) {
	cases := []struct {
		name   string
		status int
		meta   map[string]any
	}{
		{"not_found", http.StatusNotFound, map[string]any{"error": "user not found"}},
		{"invalid_json", http.StatusBadRequest, map[string]any{"error": "invalid_json"}},
		{"invalid_role", http.StatusBadRequest, map[string]any{"error": "invalid_role", "attempted_role": "superking"}},
		{"repo_failure", http.StatusInternalServerError, map[string]any{"error": "repo_failure"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &captureRecorder{}
			h := &Handler{adminAudit: rec}
			req := httptest.NewRequest(http.MethodPut, "/api/users/u-target", nil)
			req = req.WithContext(WithClaims(req.Context(), &Claims{UserID: "u-admin", Role: RoleAdmin}))

			h.recordUserUpdate(req, "u-target", c.status, false, c.meta)

			if len(rec.events) != 1 {
				t.Fatalf("events = %d, want 1", len(rec.events))
			}
			ev := rec.events[0]
			if ev.Success {
				t.Errorf("success=true для failure case %s", c.name)
			}
			if ev.StatusCode != c.status {
				t.Errorf("status = %d, want %d", ev.StatusCode, c.status)
			}
		})
	}
}

// TestRecordUserUpdate_UnauthenticatedActor — middleware не
// отработал → claims=nil → actor=nil, event всё равно пишется.
func TestRecordUserUpdate_UnauthenticatedActor(t *testing.T) {
	rec := &captureRecorder{}
	h := &Handler{adminAudit: rec}
	req := httptest.NewRequest(http.MethodPut, "/api/users/u-target", nil)
	h.recordUserUpdate(req, "u-target", http.StatusForbidden, false, nil)

	if len(rec.events) != 1 {
		t.Fatal("event не записан при nil claims")
	}
	if rec.events[0].ActorUserID != nil {
		t.Errorf("actor = %v, want nil", rec.events[0].ActorUserID)
	}
}

// TestRecordUserUpdate_EmailChange_NoEmailInMetadata — критичный
// privacy regression guard. Даже если caller захочет положить
// raw email в metadata, captureRecorder захватит это. Handler
// должен класть только флаг `email_changed`.
func TestRecordUserUpdate_EmailChange_NoEmailInMetadata(t *testing.T) {
	rec := &captureRecorder{}
	h := &Handler{adminAudit: rec}
	req := httptest.NewRequest(http.MethodPut, "/api/users/u-target", nil)
	req = req.WithContext(WithClaims(req.Context(), &Claims{UserID: "u-admin", Role: RoleAdmin}))

	// Правильный shape metadata для email-change:
	h.recordUserUpdate(req, "u-target", http.StatusOK, true, map[string]any{
		"changed_fields":  []string{"email"},
		"email_changed":   true,
		"old_email_empty": false,
	})

	meta := rec.events[0].Metadata.(map[string]any)
	if meta["email_changed"] != true {
		t.Errorf("email_changed flag не пишется")
	}
	// Критично: никаких raw email-строк.
	for k, v := range meta {
		if s, ok := v.(string); ok {
			if contains(s, "@") && k != "changed_fields" {
				t.Errorf("metadata[%q] = %q содержит '@' — возможно утечка email", k, s)
			}
		}
	}
}


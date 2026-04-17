package adminaudit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/shadowai/backend/internal/domain"
)

type stubRepo struct {
	inserted []*domain.AdminEvent
	err      error
}

func (s *stubRepo) Insert(_ context.Context, e *domain.AdminEvent) error {
	if s.err != nil {
		return s.err
	}
	s.inserted = append(s.inserted, e)
	return nil
}

// TestService_Record_MarshalsMetadata — struct metadata превращается
// в JSON string; сохраняются Action/Resource/Success/ActorUserID.
func TestService_Record_MarshalsMetadata(t *testing.T) {
	repo := &stubRepo{}
	svc := NewService(repo)

	actor := "u-admin"
	svc.Record(context.Background(), Event{
		ActorUserID: &actor,
		Action:      "read", Resource: "audit_logs",
		Path: "/api/audit/logs", Method: "GET", StatusCode: 200, Success: true,
		Metadata: map[string]any{"limit": 50, "filter": "blocked"},
	})
	if len(repo.inserted) != 1 {
		t.Fatalf("got %d inserts, want 1", len(repo.inserted))
	}
	ev := repo.inserted[0]
	if ev.Action != "read" || ev.Resource != "audit_logs" || !ev.Success {
		t.Errorf("event = %+v", ev)
	}
	if ev.ActorUserID == nil || *ev.ActorUserID != "u-admin" {
		t.Errorf("actor = %v", ev.ActorUserID)
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(ev.MetadataJSON), &meta); err != nil {
		t.Fatalf("metadata not JSON: %v (%q)", err, ev.MetadataJSON)
	}
	if int(meta["limit"].(float64)) != 50 {
		t.Errorf("limit in metadata = %v", meta["limit"])
	}
}

// TestService_Record_NoMetadata — без Metadata MetadataJSON = "".
func TestService_Record_NoMetadata(t *testing.T) {
	repo := &stubRepo{}
	svc := NewService(repo)
	svc.Record(context.Background(), Event{Action: "erase", Resource: "user"})
	if repo.inserted[0].MetadataJSON != "" {
		t.Errorf("metadata = %q, want empty", repo.inserted[0].MetadataJSON)
	}
}

// TestService_Record_NilRepo — safe no-op (dev/tests без БД).
func TestService_Record_NilRepo(t *testing.T) {
	svc := NewService(nil)
	// Must not panic.
	svc.Record(context.Background(), Event{Action: "read"})
}

// TestService_Record_RepoError_DoesNotPanic — insert fail → logged,
// caller не ломается (admin-audit fail-open для availability).
func TestService_Record_RepoError_DoesNotPanic(t *testing.T) {
	repo := &stubRepo{err: errors.New("db down")}
	svc := NewService(repo)
	// Must not panic; error is logged (checking log output здесь не
	// трогаем — достаточно проверить что функция завершается).
	svc.Record(context.Background(), Event{Action: "read"})
}

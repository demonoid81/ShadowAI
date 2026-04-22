//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// Compiled only under -tags enterprise.
//
// Package siem реализует PR-S1: mirror admin_event_logs в внешний
// HTTP sink (Splunk HEC, Elastic ingest gateway, custom collector).
//
// Архитектура: fan-out recorder, не async exporter из БД.
//
//	handler → FanoutAdminRecorder → [adminaudit.Service (PG) + siem.HTTPRecorder]
//
// Reliability: fail-open. Недоступность SIEM не ломает primary
// request path. PostgreSQL admin_event_logs остаётся source of
// truth; SIEM — дополнительный evidence stream.
//
// Privacy contract: SIEM получает РОВНО ТО ЖЕ, что admin_event_logs,
// без enrichment. Никаких raw emails/bodies/tokens/SQL.
package siem

import (
	"context"
	"time"

	"github.com/shadowai/backend/internal/adminaudit"
)

// Event — transport-neutral shape для SIEM. На v1 — прямое
// зеркало adminaudit.Event + CreatedAt (момент отправки, а не
// insert в БД — в sinks обычно это одно и то же, но явно).
type Event struct {
	ActorUserID *string `json:"actor_user_id,omitempty"`
	Action      string  `json:"action"`
	Resource    string  `json:"resource"`
	TargetID    string  `json:"target_id,omitempty"`
	Path        string  `json:"path,omitempty"`
	Method      string  `json:"method,omitempty"`
	StatusCode  int     `json:"status_code"`
	Success     bool    `json:"success"`
	Metadata    any     `json:"metadata,omitempty"`
	CreatedAt   string  `json:"created_at"`
}

// Recorder — SIEM sink abstraction. Synchronous + no return (fail-open).
// Ошибки не пропагируют в caller.
type Recorder interface {
	Record(ctx context.Context, ev Event)
}

// FromAdminEvent конвертирует adminaudit.Event → siem.Event.
// CreatedAt фиксируется в момент конвертации (UTC).
func FromAdminEvent(ev adminaudit.Event) Event {
	return Event{
		ActorUserID: ev.ActorUserID,
		Action:      ev.Action,
		Resource:    ev.Resource,
		TargetID:    ev.TargetID,
		Path:        ev.Path,
		Method:      ev.Method,
		StatusCode:  ev.StatusCode,
		Success:     ev.Success,
		Metadata:    ev.Metadata,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// NoopRecorder — safe default, когда SIEM_ENABLED=false.
// Реализует Recorder с полным no-op поведением.
type NoopRecorder struct{}

func (NoopRecorder) Record(_ context.Context, _ Event) {}

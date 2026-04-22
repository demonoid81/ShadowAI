package domain

import "time"

// AdminEvent — запись в admin_event_logs (PR-D).
// Отдельная сущность от AuditLog: admin actions имеют разный lifecycle,
// privacy-контур и analytics path.
//
// ActorUserID может быть nil для системных операций (purge scheduler,
// CLI без JWT context'а).
//
// MetadataJSON — произвольный summary (filters, counters, mode='cli'|
// 'scheduler'). Не содержит raw bodies / SQL / secrets.
type AdminEvent struct {
	ID           string    `json:"id"`
	ActorUserID  *string   `json:"actor_user_id,omitempty"`
	Action       string    `json:"action"`
	Resource     string    `json:"resource"`
	TargetID     string    `json:"target_id,omitempty"`
	Path         string    `json:"path"`
	Method       string    `json:"method"`
	StatusCode   int       `json:"status_code"`
	Success      bool      `json:"success"`
	MetadataJSON string    `json:"metadata_json,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

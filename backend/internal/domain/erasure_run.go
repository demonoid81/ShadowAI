package domain

import "time"

// ErasureRun — запись о выполненной erasure-операции.
// target_user_id остаётся даже после удаления user-row (tombstone).
// initiated_by_user_id может стать NULL, если admin-инициатор потом
// был сам erased.
type ErasureRun struct {
	ID                 string     `json:"id"`
	TargetUserID       string     `json:"target_user_id"`
	InitiatedByUserID  *string    `json:"initiated_by_user_id,omitempty"`
	AuditRowsScrubbed  int        `json:"audit_rows_scrubbed"`
	BudgetsDeleted     int        `json:"budgets_deleted"`
	CompletedAt        time.Time  `json:"completed_at"`
	Notes              *string    `json:"notes,omitempty"`
}

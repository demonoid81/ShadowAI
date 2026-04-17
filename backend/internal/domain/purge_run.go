package domain

import "time"

// PurgeRun — запись об операции purge audit_logs.
//
// CompletedAt = nil означает "не завершено" (это возможно только в
// транзитном состоянии внутри одного вызова RecordPurgeRun; finalized
// записи всегда завершены). Отдельный "in-progress" статус не
// выделяется — purge быстрый операционный процесс.
type PurgeRun struct {
	ID          string     `json:"id"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Cutoff      time.Time  `json:"cutoff"`
	RowsDeleted int        `json:"rows_deleted"`
}

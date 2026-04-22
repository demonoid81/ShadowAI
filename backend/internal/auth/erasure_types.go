package auth

// Licensing note (see ENTERPRISE.md):
//
// Типы ErasureStatus и ErasureResult — core-level data contract
// (Apache 2.0), чтобы auth.Handler.EraseUser компилировался в
// Core-сборке (nil-safe через h.eraser == nil → 503). Сама
// реализация (ErasureService + транзакция + scrub) — в erasure.go
// под //go:build enterprise.

// ErasureStatus — фиксированное множество возможных исходов EraseUser.
// Клиент (admin UI) ориентируется именно на это поле, не на HTTP status code.
type ErasureStatus string

const (
	ErasureCompleted     ErasureStatus = "completed"
	ErasureAlreadyErased ErasureStatus = "already_erased"
	ErasureNotFound      ErasureStatus = "not_found"
)

// ErasureResult — итог выполнения EraseUser.
// AuditRowsScrubbed/BudgetsDeleted валидны только при Completed.
type ErasureResult struct {
	UserID            string        `json:"user_id"`
	Status            ErasureStatus `json:"status"`
	AuditRowsScrubbed int           `json:"audit_rows_scrubbed,omitempty"`
	BudgetsDeleted    int           `json:"budgets_deleted,omitempty"`
}

//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
//
// Package legalhold реализует судебный/regulatory hold поверх
// пользователей. Блокирует DSAR/erasure для user'ов под active
// hold (GDPR Art.17(3)b/c/e carve-out: erasure duty уступает
// legal obligation).
package legalhold

import (
	"context"
	"time"
)

// Status — состояние legal hold в L2.3/L5 workflow.
//
//   - Pending        — создан, ждёт approve (НЕ блокирует DSAR).
//   - Active         — approve'нут другим admin, блокирует DSAR
//     и участвует в retention-aware purge.
//   - ReleasePending — PR-L5: release запрошен, ждёт второго
//     approver. ДSAR и purge protection ОСТАЮТСЯ в силе.
//   - Released       — финально снят (approve release или reject).
type Status string

const (
	StatusPending        Status = "pending"
	StatusActive         Status = "active"
	StatusReleasePending Status = "release_pending" // PR-L5
	StatusReleased       Status = "released"
)

const (
	ScopeWholeUser = "whole_user"
	ScopeDateRange = "date_range"
	ScopeQuery     = "query_scope"
)

// Hold — одна запись в legal_holds.
//
// L2.3: Status, ApprovedAt, ApprovedBy.
// L5: ReleaseRequestedAt, ReleaseRequestedBy, ScopeType, ScopeDateFrom, ScopeDateTo.
type Hold struct {
	ID           string
	OrgID        string
	TargetUserID string
	CaseRef      string
	Reason       string
	Status       Status
	CreatedBy    *string
	CreatedAt    time.Time
	ApprovedAt   *time.Time
	ApprovedBy   *string
	// L5: release request audit (set when active → release_pending).
	ReleaseRequestedAt *time.Time
	ReleaseRequestedBy *string
	// ReleasedAt/ReleasedBy set on final release (approve_release or reject path).
	ReleasedAt *time.Time
	ReleasedBy *string
	IsActive   bool
	// L5 scope fields. Default: ScopeType="whole_user" (backward compat).
	ScopeType         string
	ScopeDateFrom     *time.Time
	ScopeDateTo       *time.Time
	ScopeQueryJSON    string
	ScopeQueryHash    string
	ScopeQueryVersion int
}

// BulkItemResult — результат одной операции в bulk approve/reject.
type BulkItemResult struct {
	ID      string `json:"id"`
	Success bool   `json:"success"`
	Status  Status `json:"status,omitempty"`
	Error   string `json:"error,omitempty"` // machine-readable error code
}

// HoldChecker — минимальный интерфейс, который ErasureService
// использует для pre-tx check. Реализуется *Service.
//
// PR-L5: HasActiveHold блокирует для 'active' И 'release_pending' —
// release_pending остаётся legally binding до ApproveRelease.
type HoldChecker interface {
	HasActiveHold(ctx context.Context, userID string) (bool, error)
}

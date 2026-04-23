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

// Status — состояние legal hold в L2.3 4-eyes workflow.
//   - Pending  — создан, ждёт approve (ещё НЕ блокирует DSAR).
//   - Active   — approve'нут другим admin, блокирует DSAR и
//     участвует в retention-aware purge.
//   - Released — либо released после active, либо rejected из
//     pending.
//
// Hot-path check (HasActiveHold, purge NOT EXISTS) использует
// именно Status = 'active', не is_active.
type Status string

const (
	StatusPending  Status = "pending"
	StatusActive   Status = "active"
	StatusReleased Status = "released"
)

// Hold — одна запись в legal_holds.
//
// L2.3: добавлены Status, ApprovedAt, ApprovedBy. IsActive
// сохраняется как производное от Status (active ↔ true) для
// backward compat.
type Hold struct {
	ID           string
	TargetUserID string
	CaseRef      string
	Reason       string
	Status       Status
	CreatedBy    *string
	CreatedAt    time.Time
	ApprovedAt   *time.Time
	ApprovedBy   *string
	ReleasedAt   *time.Time
	ReleasedBy   *string
	IsActive     bool
}

// HoldChecker — минимальный интерфейс, который ErasureService
// использует для pre-tx check. Реализуется *Service.
type HoldChecker interface {
	HasActiveHold(ctx context.Context, userID string) (bool, error)
}

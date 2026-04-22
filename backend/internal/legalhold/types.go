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

// Hold — одна запись в legal_holds. После release is_active=false,
// released_at/released_by заполняются, row остаётся для audit.
type Hold struct {
	ID           string
	TargetUserID string
	CaseRef      string
	Reason       string
	CreatedBy    *string
	CreatedAt    time.Time
	ReleasedAt   *time.Time
	ReleasedBy   *string
	IsActive     bool
}

// HoldChecker — минимальный интерфейс, который ErasureService
// использует для pre-tx check. Реализуется *Service.
type HoldChecker interface {
	HasActiveHold(ctx context.Context, userID string) (bool, error)
}

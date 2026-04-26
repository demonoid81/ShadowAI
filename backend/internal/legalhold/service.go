//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package legalhold

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Sentinel errors для различения validation / config / runtime
// failures в handler'е. Caller мапит их в HTTP status codes:
//
//   ErrValidation    → 400 (bad request, generic message)
//   ErrNotConfigured → 503 (service unavailable)
//   everything else  → 500 (internal, generic message)
//
// Raw err.Error() строки НЕ должны уходить клиенту — admin event
// metadata пишет machine-readable code вместо этого (PR-L1.1).
var (
	ErrValidation    = errors.New("legalhold: validation failed")
	ErrNotConfigured = errors.New("legalhold: service not configured")
)

// IsValidation — handler helper для split validation vs runtime.
func IsValidation(err error) bool { return errors.Is(err, ErrValidation) }

// IsNotConfigured — handler helper.
func IsNotConfigured(err error) bool { return errors.Is(err, ErrNotConfigured) }

// Repository — persistence interface для Service. Реализация —
// PGRepository. Тесты mock'ают через in-memory impl.
type Repository interface {
	Create(ctx context.Context, h *Hold) (*Hold, error)
	// PR-L5: Release → RequestRelease (active → release_pending).
	// BREAKING CHANGE from L2.3: was immediate active → released.
	// See migration 020 and handler documentation.
	Release(ctx context.Context, id, requesterID string) (*Hold, error)
	HasActiveHold(ctx context.Context, userID string) (bool, error)
	List(ctx context.Context) ([]Hold, error)
	// PR-L2 + L2.3 + L5: bulk lookup для retention-aware purge.
	// Возвращает target_user_id'ы с status IN ('active','release_pending').
	// release_pending остаётся legally blocking до ApproveRelease.
	ActiveUserIDs(ctx context.Context) ([]string, error)
	// PR-L2.3 4-eyes: перевод pending → active.
	Approve(ctx context.Context, id, approverID string) (*Hold, error)
	// PR-L2.3: pending → released (rejected / cancelled).
	Reject(ctx context.Context, id, rejectorID string) (*Hold, error)
	// PR-L5: release 4-eyes workflow.
	ApproveRelease(ctx context.Context, id, approverID string) (*Hold, error)
	RejectRelease(ctx context.Context, id, rejectorID string) (*Hold, error)
	// PR-L5: SLA visibility — pending holds older than threshold.
	PendingOlderThan(ctx context.Context, threshold time.Duration) ([]Hold, error)
}

// Service — тонкая обёртка над repo. Валидация входа (non-empty
// case_ref/reason) + prop'ает ErrAlreadyActive/ErrNotActive как
// есть (handler их map'ит в HTTP codes).
type Service struct {
	repo Repository
}

// NewService. nil-safe: методы на *Service=nil возвращают ошибку,
// а не panic. HasActiveHold на nil Service fail-closed: возвращает
// (true, err) чтобы erasure не выполнилась при misconfigured env.
// В реальности bundle не создаётся с nil legalhold — это защитная
// мера.
func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

// CreateHold — apply hold. CaseRef и Reason обязательны (это
// compliance-эссенциальные поля). creator может быть "" для
// системных операций (CLI), но на handler-level всегда заполняется
// из claims.
func (s *Service) CreateHold(ctx context.Context, targetUserID, caseRef, reason, createdBy string) (*Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(targetUserID) == "" {
		return nil, fmt.Errorf("target_user_id required: %w", ErrValidation)
	}
	if strings.TrimSpace(caseRef) == "" {
		return nil, fmt.Errorf("case_ref required: %w", ErrValidation)
	}
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("reason required: %w", ErrValidation)
	}
	h := &Hold{
		TargetUserID: targetUserID,
		CaseRef:      strings.TrimSpace(caseRef),
		Reason:       strings.TrimSpace(reason),
	}
	if createdBy != "" {
		c := createdBy
		h.CreatedBy = &c
	}
	return s.repo.Create(ctx, h)
}

// ReleaseHold — PR-L5 BREAKING CHANGE: теперь означает RequestRelease
// (active → release_pending), не immediate release.
// Двухшаговый процесс: RequestRelease + ApproveRelease (другим admin).
//
// Идемпотентность изменилась:
//   - active → release_pending (success, 200)
//   - release_pending → ErrAlreadyReleasePending (409, повторный запрос явный конфликт)
//   - released → ErrNotActive (200 "already_released" — идемпотентно)
func (s *Service) ReleaseHold(ctx context.Context, id, requesterID string) (*Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("id required: %w", ErrValidation)
	}
	return s.repo.Release(ctx, id, requesterID)
}

// ApproveRelease — PR-L5: 4-eyes перевод release_pending → released.
// approverID должен отличаться от того, кто запросил release.
func (s *Service) ApproveRelease(ctx context.Context, id, approverID string) (*Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("id required: %w", ErrValidation)
	}
	if strings.TrimSpace(approverID) == "" {
		return nil, fmt.Errorf("approver_id required: %w", ErrValidation)
	}
	return s.repo.ApproveRelease(ctx, id, approverID)
}

// RejectRelease — PR-L5: перевод release_pending → active (release rejected).
func (s *Service) RejectRelease(ctx context.Context, id, rejectorID string) (*Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("id required: %w", ErrValidation)
	}
	return s.repo.RejectRelease(ctx, id, rejectorID)
}

// BulkApprove — PR-L5: bulk перевод pending → active.
// Per-item semantics: один failing item не rollback'ает остальные.
// Возвращает полный список результатов, включая partial failures.
func (s *Service) BulkApprove(ctx context.Context, ids []string, approverID string) ([]BulkItemResult, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("ids required: %w", ErrValidation)
	}
	if strings.TrimSpace(approverID) == "" {
		return nil, fmt.Errorf("approver_id required: %w", ErrValidation)
	}
	results := make([]BulkItemResult, 0, len(ids))
	for _, id := range ids {
		hold, err := s.repo.Approve(ctx, id, approverID)
		if err != nil {
			results = append(results, BulkItemResult{
				ID:    id,
				Error: bulkErrorCode(err),
			})
			continue
		}
		results = append(results, BulkItemResult{
			ID:      id,
			Success: true,
			Status:  hold.Status,
		})
	}
	return results, nil
}

// BulkReject — PR-L5: bulk перевод pending → released.
// Per-item semantics: partial failure не rollback'ает остальные.
func (s *Service) BulkReject(ctx context.Context, ids []string, rejectorID string) ([]BulkItemResult, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("ids required: %w", ErrValidation)
	}
	results := make([]BulkItemResult, 0, len(ids))
	for _, id := range ids {
		hold, err := s.repo.Reject(ctx, id, rejectorID)
		if err != nil {
			results = append(results, BulkItemResult{
				ID:    id,
				Error: bulkErrorCode(err),
			})
			continue
		}
		results = append(results, BulkItemResult{
			ID:      id,
			Success: true,
			Status:  hold.Status,
		})
	}
	return results, nil
}

// PendingOlderThan — PR-L5: SLA visibility. Возвращает pending holds,
// созданные более threshold назад. Без фонового воркера: query-on-demand.
func (s *Service) PendingOlderThan(ctx context.Context, threshold time.Duration) ([]Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if threshold <= 0 {
		return nil, fmt.Errorf("threshold must be positive: %w", ErrValidation)
	}
	return s.repo.PendingOlderThan(ctx, threshold)
}

// bulkErrorCode — machine-readable error code для BulkItemResult.
func bulkErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrNotPending):
		return "not_pending"
	case errors.Is(err, ErrSelfApproval):
		return "self_approval"
	case errors.Is(err, ErrNotReleasePending):
		return "not_release_pending"
	default:
		return "internal_error"
	}
}

// HasActiveHold — satisfies HoldChecker interface. Возвращает
// (has, err). Caller (ErasureService) трактует err как fail-closed
// (лучше отклонить erase с 500, чем erase'нуть пользователя под
// hold'ом потому что мы не смогли прочитать таблицу).
func (s *Service) HasActiveHold(ctx context.Context, userID string) (bool, error) {
	if s == nil || s.repo == nil {
		// Fail-closed: если Service не сконфигурирован, считаем
		// что hold есть — erasure отвергается. Compliance выше
		// availability.
		return true, ErrNotConfigured
	}
	return s.repo.HasActiveHold(ctx, userID)
}

// List возвращает все hold-ы, active first.
func (s *Service) List(ctx context.Context) ([]Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	return s.repo.List(ctx)
}

// ActiveUserIDs — PR-L2: для retention-aware audit-purge scheduler.
// nil Service возвращает (nil, ErrNotConfigured) — scheduler
// трактует как fail-closed (skip purge на этом тике).
func (s *Service) ActiveUserIDs(ctx context.Context) ([]string, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	return s.repo.ActiveUserIDs(ctx)
}

// Approve — PR-L2.3: 4-eyes перевод pending → active. approverID
// должен отличаться от creator — проверка на repo-слое (FOR UPDATE
// lock + cmp с created_by). Возвращает ErrSelfApproval, если
// approver == creator; ErrNotFound, если id не существует;
// ErrNotPending, если hold уже approve'нут/released.
func (s *Service) Approve(ctx context.Context, id, approverID string) (*Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("id required: %w", ErrValidation)
	}
	if strings.TrimSpace(approverID) == "" {
		return nil, fmt.Errorf("approver_id required: %w", ErrValidation)
	}
	return s.repo.Approve(ctx, id, approverID)
}

// Reject — PR-L2.3: перевод pending → released (rejected /
// cancelled). rejectorID фиксируется в released_by. Отличие от
// Release: Reject работает только на pending, Release — только на
// active.
func (s *Service) Reject(ctx context.Context, id, rejectorID string) (*Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("id required: %w", ErrValidation)
	}
	return s.repo.Reject(ctx, id, rejectorID)
}

// IsNotPending — helper для handler'а: approve/reject на
// active/released hold → 409 Conflict.
func IsNotPending(err error) bool { return errors.Is(err, ErrNotPending) }

// IsSelfApproval — helper для handler'а: approver == creator → 403
// (4-eyes policy violation).
func IsSelfApproval(err error) bool { return errors.Is(err, ErrSelfApproval) }

// IsPendingNotReleasable — PR-L2.3: Release вызван на pending hold.
// Handler возвращает 409 "use reject to cancel" вместо ошибочного
// 200 "already_released".
func IsPendingNotReleasable(err error) bool { return errors.Is(err, ErrPendingNotReleasable) }

// IsAlreadyActive — helper для handler'а, чтобы не импортировать
// errors package ради одной проверки.
func IsAlreadyActive(err error) bool { return errors.Is(err, ErrAlreadyActive) }

// IsNotActive — helper для handler'а (идемпотентный release).
func IsNotActive(err error) bool { return errors.Is(err, ErrNotActive) }

// IsNotFound — helper для handler'а (release of missing id).
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// PR-L5 error predicates.

// IsNotReleasePending — ApproveRelease/RejectRelease на hold не в
// release_pending → 409 Conflict.
func IsNotReleasePending(err error) bool { return errors.Is(err, ErrNotReleasePending) }

// IsSelfReleaseApproval — approver совпадает с release requester → 403.
func IsSelfReleaseApproval(err error) bool { return errors.Is(err, ErrSelfReleaseApproval) }

// IsAlreadyReleasePending — RequestRelease на hold уже в
// release_pending → 409 Conflict.
func IsAlreadyReleasePending(err error) bool { return errors.Is(err, ErrAlreadyReleasePending) }

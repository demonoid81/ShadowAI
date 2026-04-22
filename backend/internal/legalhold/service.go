//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package legalhold

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	Release(ctx context.Context, id, releasedBy string) (*Hold, error)
	HasActiveHold(ctx context.Context, userID string) (bool, error)
	List(ctx context.Context) ([]Hold, error)
	// PR-L2: bulk lookup для retention-aware purge. Возвращает
	// target_user_id'ы всех is_active=true записей (каждый UUID
	// ровно один раз — DB partial-unique index гарантирует).
	ActiveUserIDs(ctx context.Context) ([]string, error)
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

// ReleaseHold — снимает hold. Идемпотентность: повторный release
// → возвращает (nil, ErrNotActive); handler переводит в
// "already_released" 200-ответ без ошибки.
func (s *Service) ReleaseHold(ctx context.Context, id, releasedBy string) (*Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("id required: %w", ErrValidation)
	}
	return s.repo.Release(ctx, id, releasedBy)
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

// IsAlreadyActive — helper для handler'а, чтобы не импортировать
// errors package ради одной проверки.
func IsAlreadyActive(err error) bool { return errors.Is(err, ErrAlreadyActive) }

// IsNotActive — helper для handler'а (идемпотентный release).
func IsNotActive(err error) bool { return errors.Is(err, ErrNotActive) }

// IsNotFound — helper для handler'а (release of missing id).
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

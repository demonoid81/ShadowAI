//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package legalhold

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Repository — persistence interface для Service. Реализация —
// PGRepository. Тесты mock'ают через in-memory impl.
type Repository interface {
	Create(ctx context.Context, h *Hold) (*Hold, error)
	Release(ctx context.Context, id, releasedBy string) (*Hold, error)
	HasActiveHold(ctx context.Context, userID string) (bool, error)
	List(ctx context.Context) ([]Hold, error)
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
		return nil, fmt.Errorf("legalhold: service not configured")
	}
	if strings.TrimSpace(targetUserID) == "" {
		return nil, fmt.Errorf("legalhold: target_user_id required")
	}
	if strings.TrimSpace(caseRef) == "" {
		return nil, fmt.Errorf("legalhold: case_ref required")
	}
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("legalhold: reason required")
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
		return nil, fmt.Errorf("legalhold: service not configured")
	}
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("legalhold: id required")
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
		return true, fmt.Errorf("legalhold: service not configured")
	}
	return s.repo.HasActiveHold(ctx, userID)
}

// List возвращает все hold-ы, active first.
func (s *Service) List(ctx context.Context) ([]Hold, error) {
	if s == nil || s.repo == nil {
		return nil, fmt.Errorf("legalhold: service not configured")
	}
	return s.repo.List(ctx)
}

// IsAlreadyActive — helper для handler'а, чтобы не импортировать
// errors package ради одной проверки.
func IsAlreadyActive(err error) bool { return errors.Is(err, ErrAlreadyActive) }

// IsNotActive — helper для handler'а (идемпотентный release).
func IsNotActive(err error) bool { return errors.Is(err, ErrNotActive) }

// IsNotFound — helper для handler'а (release of missing id).
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

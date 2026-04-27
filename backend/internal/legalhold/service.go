//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package legalhold

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shadowai/backend/internal/legalholdselector"
)

// Sentinel errors для различения validation / config / runtime
// failures в handler'е. Caller мапит их в HTTP status codes:
//
//	ErrValidation    → 400 (некорректный запрос, общее сообщение)
//	ErrNotConfigured → 503 (сервис недоступен)
//	прочие ошибки    → 500 (внутренняя ошибка, общее сообщение)
//
// Raw err.Error() строки НЕ должны уходить клиенту — admin event
// metadata пишет machine-readable code вместо этого (PR-L1.1).
var (
	ErrValidation        = errors.New("legalhold: validation failed")
	ErrNotConfigured     = errors.New("legalhold: service not configured")
	ErrUnsupportedScope  = errors.New("legalhold: unsupported scope type")
	ErrInvalidScopeRange = errors.New("legalhold: invalid scope range")
)

// IsValidation — handler helper для split validation vs runtime.
func IsValidation(err error) bool { return errors.Is(err, ErrValidation) }

// IsNotConfigured — handler helper.
func IsNotConfigured(err error) bool { return errors.Is(err, ErrNotConfigured) }

func IsUnsupportedScope(err error) bool { return errors.Is(err, ErrUnsupportedScope) }

func IsInvalidScopeRange(err error) bool { return errors.Is(err, ErrInvalidScopeRange) }

func IsInvalidSelector(err error) bool { return legalholdselector.IsInvalid(err) }

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

type ScopedRepository interface {
	CreateInOrg(ctx context.Context, h *Hold, orgID string) (*Hold, error)
	ApproveInOrg(ctx context.Context, id, approverID, orgID string) (*Hold, error)
	RejectInOrg(ctx context.Context, id, rejectorID, orgID string) (*Hold, error)
	ReleaseInOrg(ctx context.Context, id, requesterID, orgID string) (*Hold, error)
	ApproveReleaseInOrg(ctx context.Context, id, approverID, orgID string) (*Hold, error)
	RejectReleaseInOrg(ctx context.Context, id, rejectorID, orgID string) (*Hold, error)
	ListInOrg(ctx context.Context, orgID string) ([]Hold, error)
	PendingOlderThanInOrg(ctx context.Context, threshold time.Duration, orgID string) ([]Hold, error)
}

type QueryPreviewRepository interface {
	PreviewQueryScope(ctx context.Context, orgID, targetUserID string, compiled legalholdselector.Compiled) (QueryScopePreviewStats, error)
}

type QueryScopePreviewStats struct {
	MatchedRows     int
	OldestCreatedAt *time.Time
	NewestCreatedAt *time.Time
}

type QueryScopePreviewResult struct {
	ScopeType       string
	SelectorHash    string
	MatchedRows     int
	OldestCreatedAt *time.Time
	NewestCreatedAt *time.Time
	Explanation     string
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
	return s.CreateHoldInOrg(ctx, targetUserID, caseRef, reason, createdBy, "")
}

func (s *Service) CreateHoldInOrg(ctx context.Context, targetUserID, caseRef, reason, createdBy, orgID string) (*Hold, error) {
	return s.CreateScopedHoldInOrg(ctx, targetUserID, caseRef, reason, createdBy, orgID, ScopeWholeUser, nil, nil)
}

func (s *Service) CreateScopedHoldInOrg(ctx context.Context, targetUserID, caseRef, reason, createdBy, orgID, scopeType string, scopeFrom, scopeTo *time.Time) (*Hold, error) {
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
	scopeType, scopeFrom, scopeTo, err := normalizeScope(scopeType, scopeFrom, scopeTo)
	if err != nil {
		return nil, err
	}
	h := &Hold{
		OrgID:         orgID,
		TargetUserID:  targetUserID,
		CaseRef:       strings.TrimSpace(caseRef),
		Reason:        strings.TrimSpace(reason),
		ScopeType:     scopeType,
		ScopeDateFrom: scopeFrom,
		ScopeDateTo:   scopeTo,
	}
	if createdBy != "" {
		c := createdBy
		h.CreatedBy = &c
	}
	if scoped, ok := s.repo.(ScopedRepository); ok && orgID != "" {
		return scoped.CreateInOrg(ctx, h, orgID)
	}
	return s.repo.Create(ctx, h)
}

func (s *Service) CreateQueryScopedHoldInOrg(ctx context.Context, targetUserID, caseRef, reason, createdBy, orgID string, raw json.RawMessage) (*Hold, QueryScopePreviewResult, error) {
	if s == nil || s.repo == nil {
		return nil, QueryScopePreviewResult{}, ErrNotConfigured
	}
	if strings.TrimSpace(targetUserID) == "" {
		return nil, QueryScopePreviewResult{}, fmt.Errorf("target_user_id required: %w", ErrValidation)
	}
	if strings.TrimSpace(caseRef) == "" {
		return nil, QueryScopePreviewResult{}, fmt.Errorf("case_ref required: %w", ErrValidation)
	}
	if strings.TrimSpace(reason) == "" {
		return nil, QueryScopePreviewResult{}, fmt.Errorf("reason required: %w", ErrValidation)
	}
	previewRepo, ok := s.repo.(QueryPreviewRepository)
	if !ok {
		return nil, QueryScopePreviewResult{}, ErrNotConfigured
	}
	compiled, err := legalholdselector.Compile(raw, legalholdselector.CompileOptions{ArgOffset: 3})
	if err != nil {
		return nil, QueryScopePreviewResult{}, fmt.Errorf("%w: %w", ErrValidation, err)
	}
	stats, err := previewRepo.PreviewQueryScope(ctx, orgID, targetUserID, compiled)
	if err != nil {
		return nil, QueryScopePreviewResult{}, err
	}
	h := &Hold{
		OrgID:             orgID,
		TargetUserID:      targetUserID,
		CaseRef:           strings.TrimSpace(caseRef),
		Reason:            strings.TrimSpace(reason),
		ScopeType:         ScopeQuery,
		ScopeQueryJSON:    string(compiled.NormalizedJSON),
		ScopeQueryHash:    compiled.Hash,
		ScopeQueryVersion: 1,
	}
	if createdBy != "" {
		c := createdBy
		h.CreatedBy = &c
	}
	var created *Hold
	if scoped, ok := s.repo.(ScopedRepository); ok && orgID != "" {
		created, err = scoped.CreateInOrg(ctx, h, orgID)
	} else {
		created, err = s.repo.Create(ctx, h)
	}
	if err != nil {
		return nil, QueryScopePreviewResult{}, err
	}
	return created, QueryScopePreviewResult{
		ScopeType:       ScopeQuery,
		SelectorHash:    compiled.Hash,
		MatchedRows:     stats.MatchedRows,
		OldestCreatedAt: stats.OldestCreatedAt,
		NewestCreatedAt: stats.NewestCreatedAt,
		Explanation:     "target user rows where " + compiled.Explanation,
	}, nil
}

func (s *Service) PreviewQueryScopeInOrg(ctx context.Context, targetUserID, orgID string, raw json.RawMessage) (QueryScopePreviewResult, error) {
	if s == nil || s.repo == nil {
		return QueryScopePreviewResult{}, ErrNotConfigured
	}
	if strings.TrimSpace(targetUserID) == "" {
		return QueryScopePreviewResult{}, fmt.Errorf("target_user_id required: %w", ErrValidation)
	}
	previewRepo, ok := s.repo.(QueryPreviewRepository)
	if !ok {
		return QueryScopePreviewResult{}, ErrNotConfigured
	}
	compiled, err := legalholdselector.Compile(raw, legalholdselector.CompileOptions{ArgOffset: 3})
	if err != nil {
		return QueryScopePreviewResult{}, fmt.Errorf("%w: %w", ErrValidation, err)
	}
	stats, err := previewRepo.PreviewQueryScope(ctx, orgID, targetUserID, compiled)
	if err != nil {
		return QueryScopePreviewResult{}, err
	}
	return QueryScopePreviewResult{
		ScopeType:       ScopeQuery,
		SelectorHash:    compiled.Hash,
		MatchedRows:     stats.MatchedRows,
		OldestCreatedAt: stats.OldestCreatedAt,
		NewestCreatedAt: stats.NewestCreatedAt,
		Explanation:     "target user rows where " + compiled.Explanation,
	}, nil
}

func normalizeScope(scopeType string, from, to *time.Time) (string, *time.Time, *time.Time, error) {
	scopeType = strings.TrimSpace(scopeType)
	if scopeType == "" {
		scopeType = ScopeWholeUser
	}
	switch scopeType {
	case ScopeWholeUser:
		return ScopeWholeUser, nil, nil, nil
	case ScopeDateRange:
		if from == nil || to == nil {
			return "", nil, nil, fmt.Errorf("date_range requires scope_date_from and scope_date_to: %w", ErrInvalidScopeRange)
		}
		fromUTC := from.UTC()
		toUTC := to.UTC()
		if fromUTC.After(toUTC) {
			return "", nil, nil, fmt.Errorf("scope_date_from must be <= scope_date_to: %w", ErrInvalidScopeRange)
		}
		return ScopeDateRange, &fromUTC, &toUTC, nil
	case ScopeQuery:
		return "", nil, nil, fmt.Errorf("query_scope unsupported in L6 v1: %w", ErrUnsupportedScope)
	default:
		return "", nil, nil, fmt.Errorf("unknown scope_type: %w", ErrUnsupportedScope)
	}
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
	return s.ReleaseHoldInOrg(ctx, id, requesterID, "")
}

func (s *Service) ReleaseHoldInOrg(ctx context.Context, id, requesterID, orgID string) (*Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("id required: %w", ErrValidation)
	}
	if scoped, ok := s.repo.(ScopedRepository); ok && orgID != "" {
		return scoped.ReleaseInOrg(ctx, id, requesterID, orgID)
	}
	return s.repo.Release(ctx, id, requesterID)
}

// ApproveRelease — PR-L5: 4-eyes перевод release_pending → released.
// approverID должен отличаться от того, кто запросил release.
func (s *Service) ApproveRelease(ctx context.Context, id, approverID string) (*Hold, error) {
	return s.ApproveReleaseInOrg(ctx, id, approverID, "")
}

func (s *Service) ApproveReleaseInOrg(ctx context.Context, id, approverID, orgID string) (*Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("id required: %w", ErrValidation)
	}
	if strings.TrimSpace(approverID) == "" {
		return nil, fmt.Errorf("approver_id required: %w", ErrValidation)
	}
	if scoped, ok := s.repo.(ScopedRepository); ok && orgID != "" {
		return scoped.ApproveReleaseInOrg(ctx, id, approverID, orgID)
	}
	return s.repo.ApproveRelease(ctx, id, approverID)
}

// RejectRelease — PR-L5: перевод release_pending → active (release rejected).
func (s *Service) RejectRelease(ctx context.Context, id, rejectorID string) (*Hold, error) {
	return s.RejectReleaseInOrg(ctx, id, rejectorID, "")
}

func (s *Service) RejectReleaseInOrg(ctx context.Context, id, rejectorID, orgID string) (*Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("id required: %w", ErrValidation)
	}
	if scoped, ok := s.repo.(ScopedRepository); ok && orgID != "" {
		return scoped.RejectReleaseInOrg(ctx, id, rejectorID, orgID)
	}
	return s.repo.RejectRelease(ctx, id, rejectorID)
}

// BulkApprove — PR-L5: bulk перевод pending → active.
// Per-item semantics: один failing item не rollback'ает остальные.
// Возвращает полный список результатов, включая partial failures.
func (s *Service) BulkApprove(ctx context.Context, ids []string, approverID string) ([]BulkItemResult, error) {
	return s.BulkApproveInOrg(ctx, ids, approverID, "")
}

func (s *Service) BulkApproveInOrg(ctx context.Context, ids []string, approverID, orgID string) ([]BulkItemResult, error) {
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
		var hold *Hold
		var err error
		if scoped, ok := s.repo.(ScopedRepository); ok && orgID != "" {
			hold, err = scoped.ApproveInOrg(ctx, id, approverID, orgID)
		} else {
			hold, err = s.repo.Approve(ctx, id, approverID)
		}
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
	return s.BulkRejectInOrg(ctx, ids, rejectorID, "")
}

func (s *Service) BulkRejectInOrg(ctx context.Context, ids []string, rejectorID, orgID string) ([]BulkItemResult, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("ids required: %w", ErrValidation)
	}
	results := make([]BulkItemResult, 0, len(ids))
	for _, id := range ids {
		var hold *Hold
		var err error
		if scoped, ok := s.repo.(ScopedRepository); ok && orgID != "" {
			hold, err = scoped.RejectInOrg(ctx, id, rejectorID, orgID)
		} else {
			hold, err = s.repo.Reject(ctx, id, rejectorID)
		}
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
	return s.PendingOlderThanInOrg(ctx, threshold, "")
}

func (s *Service) PendingOlderThanInOrg(ctx context.Context, threshold time.Duration, orgID string) ([]Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if threshold <= 0 {
		return nil, fmt.Errorf("threshold must be positive: %w", ErrValidation)
	}
	if scoped, ok := s.repo.(ScopedRepository); ok && orgID != "" {
		return scoped.PendingOlderThanInOrg(ctx, threshold, orgID)
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
	return s.ListInOrg(ctx, "")
}

func (s *Service) ListInOrg(ctx context.Context, orgID string) ([]Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if scoped, ok := s.repo.(ScopedRepository); ok && orgID != "" {
		return scoped.ListInOrg(ctx, orgID)
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
	return s.ApproveInOrg(ctx, id, approverID, "")
}

func (s *Service) ApproveInOrg(ctx context.Context, id, approverID, orgID string) (*Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("id required: %w", ErrValidation)
	}
	if strings.TrimSpace(approverID) == "" {
		return nil, fmt.Errorf("approver_id required: %w", ErrValidation)
	}
	if scoped, ok := s.repo.(ScopedRepository); ok && orgID != "" {
		return scoped.ApproveInOrg(ctx, id, approverID, orgID)
	}
	return s.repo.Approve(ctx, id, approverID)
}

// Reject — PR-L2.3: перевод pending → released (rejected /
// cancelled). rejectorID фиксируется в released_by. Отличие от
// Release: Reject работает только на pending, Release — только на
// active.
func (s *Service) Reject(ctx context.Context, id, rejectorID string) (*Hold, error) {
	return s.RejectInOrg(ctx, id, rejectorID, "")
}

func (s *Service) RejectInOrg(ctx context.Context, id, rejectorID, orgID string) (*Hold, error) {
	if s == nil || s.repo == nil {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("id required: %w", ErrValidation)
	}
	if scoped, ok := s.repo.(ScopedRepository); ok && orgID != "" {
		return scoped.RejectInOrg(ctx, id, rejectorID, orgID)
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

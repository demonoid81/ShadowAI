//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// PR-G4: org-level aggregate budget service.

package orgbudget

import (
	"context"
	"fmt"
	"log"
	"math"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/domain"
)

// Repo is the storage interface used by Service (allows in-memory mocks in tests).
type Repo interface {
	GetPolicy(ctx context.Context, orgID string) (*domain.OrgBudgetPolicy, error)
	UpsertPolicy(ctx context.Context, p *domain.OrgBudgetPolicy) error
	GetCurrentUsage(ctx context.Context, orgID string) (*domain.OrgBudgetUsage, error)
	AddSpend(ctx context.Context, orgID string, deltaCents int64) error
}

// Service implements proxy.OrgBudgetChecker and provides the full budget management API.
type Service struct {
	repo       Repo
	adminAudit adminaudit.Recorder
}

func NewService(repo Repo, adminAudit adminaudit.Recorder) *Service {
	return &Service{repo: repo, adminAudit: adminAudit}
}

// GetStatus returns policy + current-month usage for an org.
func (s *Service) GetStatus(ctx context.Context, orgID string) (*domain.OrgBudgetStatus, error) {
	policy, err := s.repo.GetPolicy(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		policy = &domain.OrgBudgetPolicy{
			OrgID: orgID,
			Mode:  domain.OrgBudgetDisabled,
		}
	}
	usage, err := s.repo.GetCurrentUsage(ctx, orgID)
	if err != nil {
		return nil, err
	}
	remaining := int64(math.MaxInt64)
	if policy.MonthlyLimitCents > 0 {
		remaining = policy.MonthlyLimitCents - usage.SpentCents
	}
	return &domain.OrgBudgetStatus{
		Policy:    *policy,
		Usage:     *usage,
		Remaining: remaining,
	}, nil
}

// UpsertPolicy saves a new or updated org budget policy.
func (s *Service) UpsertPolicy(ctx context.Context, p *domain.OrgBudgetPolicy, actorUserID string) error {
	p.UpdatedBy = &actorUserID
	if err := s.repo.UpsertPolicy(ctx, p); err != nil {
		return err
	}
	if s.adminAudit != nil {
		s.adminAudit.Record(ctx, adminaudit.Event{
			OrgID:      p.OrgID,
			Action:     "upsert",
			Resource:   "org_budget_policy",
			TargetID:   p.OrgID,
			Path:       "api",
			Method:     "PUT",
			StatusCode: 200,
			Success:    true,
			Metadata: map[string]any{
				"monthly_limit_cents": p.MonthlyLimitCents,
				"mode":                string(p.Mode),
			},
		})
	}
	return nil
}

// CheckBefore checks org budget before a provider call.
// Returns domain.OrgBudgetDecision (core-compatible with proxy.OrgBudgetChecker).
func (s *Service) CheckBefore(ctx context.Context, orgID string, estimatedCents int64) (domain.OrgBudgetDecision, error) {
	if orgID == "" {
		return domain.OrgBudgetDecision{Allowed: true, Mode: domain.OrgBudgetDisabled}, nil
	}
	policy, err := s.repo.GetPolicy(ctx, orgID)
	if err != nil {
		log.Printf("orgbudget: GetPolicy err (fail-open): %v", err)
		return domain.OrgBudgetDecision{Allowed: true, Mode: domain.OrgBudgetDisabled, OrgID: orgID}, nil
	}
	if policy == nil || policy.Mode == domain.OrgBudgetDisabled {
		metricDecision.WithLabelValues("allowed", string(domain.OrgBudgetDisabled)).Inc()
		return domain.OrgBudgetDecision{Allowed: true, Mode: domain.OrgBudgetDisabled, OrgID: orgID}, nil
	}

	usage, err := s.repo.GetCurrentUsage(ctx, orgID)
	if err != nil {
		log.Printf("orgbudget: GetCurrentUsage err (fail-open): %v", err)
		return domain.OrgBudgetDecision{Allowed: true, Mode: policy.Mode, OrgID: orgID}, nil
	}

	projected := usage.SpentCents + estimatedCents
	remaining := int64(math.MaxInt64)
	if policy.MonthlyLimitCents > 0 {
		remaining = policy.MonthlyLimitCents - projected
	}

	// observe always allows; enforce blocks when cap is reached.
	if policy.Mode == domain.OrgBudgetObserve {
		if policy.MonthlyLimitCents > 0 && projected >= policy.MonthlyLimitCents {
			metricDecision.WithLabelValues("soft_exceeded", string(policy.Mode)).Inc()
			s.recordBudgetEvent(ctx, orgID, "org_budget_exceeded_observe", usage.SpentCents, policy.MonthlyLimitCents)
		} else {
			metricDecision.WithLabelValues("allowed", string(policy.Mode)).Inc()
		}
		return domain.OrgBudgetDecision{Allowed: true, Mode: policy.Mode, Remaining: remaining, OrgID: orgID}, nil
	}

	// enforce
	if policy.MonthlyLimitCents > 0 && projected >= policy.MonthlyLimitCents {
		metricDecision.WithLabelValues("blocked", string(policy.Mode)).Inc()
		s.recordBudgetEvent(ctx, orgID, "org_budget_blocked", usage.SpentCents, policy.MonthlyLimitCents)
		return domain.OrgBudgetDecision{Allowed: false, Mode: policy.Mode, Remaining: remaining, OrgID: orgID}, nil
	}

	metricDecision.WithLabelValues("allowed", string(policy.Mode)).Inc()
	return domain.OrgBudgetDecision{Allowed: true, Mode: policy.Mode, Remaining: remaining, OrgID: orgID}, nil
}

// RecordActual adds actual post-call spend.
func (s *Service) RecordActual(ctx context.Context, orgID string, actualCents int64) error {
	if orgID == "" || actualCents <= 0 {
		return nil
	}
	if err := s.repo.AddSpend(ctx, orgID, actualCents); err != nil {
		log.Printf("orgbudget: AddSpend err: %v", err)
		return fmt.Errorf("orgbudget record actual: %w", err)
	}
	metricSpentCents.Add(float64(actualCents))
	return nil
}

func (s *Service) recordBudgetEvent(ctx context.Context, orgID, action string, spent, limit int64) {
	if s.adminAudit == nil {
		return
	}
	s.adminAudit.Record(ctx, adminaudit.Event{
		OrgID:      orgID,
		Action:     action,
		Resource:   "org_budget",
		TargetID:   orgID,
		Path:       "proxy",
		Method:     "POST",
		StatusCode: 0,
		Success:    false,
		Metadata: map[string]any{
			"spent_cents": spent,
			"limit_cents": limit,
		},
	})
}

// ---------------------------------------------------------------------------
// Prometheus metrics (no org_id label to avoid high cardinality)
// ---------------------------------------------------------------------------

var (
	metricDecision = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_org_budget_decisions_total",
		Help: "Total org budget decisions by outcome and policy mode.",
	}, []string{"decision", "mode"})

	metricSpentCents = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shadowai_org_budget_spent_cents_total",
		Help: "Total org-level spend recorded in cents (all orgs combined).",
	})
)

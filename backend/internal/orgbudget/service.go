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
	// AtomicCheckAndAdd serializes concurrent budget checks for this org via advisory lock.
	// Returns (spentAfter, allowed, err). When allowed=true the estimatedCents is added to usage.
	AtomicCheckAndAdd(ctx context.Context, orgID string, estimatedCents, limitCents int64, enforce bool) (int64, bool, error)
	// OrgExists returns true when the organizations table has a row with this id.
	OrgExists(ctx context.Context, orgID string) (bool, error)
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

// OrgExists delegates to the repo for the org existence pre-check in handler.
func (s *Service) OrgExists(ctx context.Context, orgID string) (bool, error) {
	return s.repo.OrgExists(ctx, orgID)
}

// UpsertPolicy saves a new or updated org budget policy.
func (s *Service) UpsertPolicy(ctx context.Context, p *domain.OrgBudgetPolicy, actorUserID string) error {
	p.UpdatedBy = &actorUserID
	if err := s.repo.UpsertPolicy(ctx, p); err != nil {
		return err
	}
	if s.adminAudit != nil {
		var actorPtr *string
		if actorUserID != "" {
			actorPtr = &actorUserID
		}
		s.adminAudit.Record(ctx, adminaudit.Event{
			ActorUserID: actorPtr,
			OrgID:       p.OrgID,
			SourceOrgID: p.OrgID, // actor operates within the same org (or global_admin)
			TargetOrgID: p.OrgID,
			Action:      "upsert",
			Resource:    "org_budget_policy",
			TargetID:    p.OrgID,
			Path:        "api",
			Method:      "PUT",
			StatusCode:  200,
			Success:     true,
			Metadata: map[string]any{
				"monthly_limit_cents": p.MonthlyLimitCents,
				"mode":                string(p.Mode),
			},
		})
	}
	return nil
}

// CheckBefore atomically checks the org cap and — if allowed — reserves the
// estimated spend via a PostgreSQL advisory lock. Concurrent requests for the
// same org are serialized so the cap can never be exceeded by racing calls.
//
// Decision.ReservedCents contains the amount added to DB usage. Callers MUST
// call Adjust(orgID, dec.ReservedCents, actualCents) after the provider call:
//   - On success:  Adjust(orgID, reserved, actual) adjusts to real cost.
//   - On failure:  Adjust(orgID, reserved, 0) refunds the full reservation.
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

	enforce := policy.Mode == domain.OrgBudgetEnforce

	if policy.Mode == domain.OrgBudgetObserve {
		// Observe mode: read-only check (no reservation needed — never blocks).
		usage, err := s.repo.GetCurrentUsage(ctx, orgID)
		if err != nil {
			log.Printf("orgbudget: GetCurrentUsage err (fail-open, observe): %v", err)
			return domain.OrgBudgetDecision{Allowed: true, Mode: policy.Mode, OrgID: orgID}, nil
		}
		projected := usage.SpentCents + estimatedCents
		remaining := int64(math.MaxInt64)
		if policy.MonthlyLimitCents > 0 {
			remaining = policy.MonthlyLimitCents - projected
		}
		if policy.MonthlyLimitCents > 0 && projected >= policy.MonthlyLimitCents {
			metricDecision.WithLabelValues("soft_exceeded", string(policy.Mode)).Inc()
			s.recordBudgetEvent(ctx, orgID, "org_budget_exceeded_observe", usage.SpentCents, policy.MonthlyLimitCents)
		} else {
			metricDecision.WithLabelValues("allowed", string(policy.Mode)).Inc()
		}
		// ReservedCents=0 for observe: proxy calls RecordActual directly after provider call.
		return domain.OrgBudgetDecision{Allowed: true, Mode: policy.Mode, Remaining: remaining, OrgID: orgID}, nil
	}

	// Enforce mode: AtomicCheckAndAdd serializes concurrent checks and reserves estimatedCents.
	spentAfter, allowed, err := s.repo.AtomicCheckAndAdd(ctx, orgID, estimatedCents, policy.MonthlyLimitCents, enforce)
	if err != nil {
		// Fix (Medium): usage read/lock failure in enforce mode → fail-closed.
		metricDecision.WithLabelValues("error_blocked", string(policy.Mode)).Inc()
		s.recordBudgetEvent(ctx, orgID, "org_budget_enforce_read_failure", 0, policy.MonthlyLimitCents)
		return domain.OrgBudgetDecision{Allowed: false, Mode: policy.Mode, OrgID: orgID}, nil
	}

	remaining := int64(math.MaxInt64)
	if policy.MonthlyLimitCents > 0 {
		remaining = policy.MonthlyLimitCents - spentAfter
	}

	if !allowed {
		metricDecision.WithLabelValues("blocked", string(policy.Mode)).Inc()
		s.recordBudgetEvent(ctx, orgID, "org_budget_blocked", spentAfter, policy.MonthlyLimitCents)
		return domain.OrgBudgetDecision{Allowed: false, Mode: policy.Mode, Remaining: remaining, OrgID: orgID}, nil
	}

	metricDecision.WithLabelValues("allowed", string(policy.Mode)).Inc()
	return domain.OrgBudgetDecision{
		Allowed: true, Mode: policy.Mode, Remaining: remaining,
		OrgID: orgID, ReservedCents: estimatedCents, // reserved in DB; caller must Adjust after call
	}, nil
}

// Adjust finalizes or refunds a reservation made by CheckBefore.
// It adds (actualCents - reservedCents) to org_budget_usage atomically.
// Call with actualCents=0 to fully refund a reservation (provider call failed).
func (s *Service) Adjust(ctx context.Context, orgID string, reservedCents, actualCents int64) error {
	delta := actualCents - reservedCents
	if delta == 0 || orgID == "" {
		if actualCents > 0 {
			metricSpentCents.Add(float64(actualCents))
		}
		return nil
	}
	if err := s.repo.AddSpend(ctx, orgID, delta); err != nil {
		log.Printf("orgbudget: Adjust err: %v", err)
		return fmt.Errorf("orgbudget adjust: %w", err)
	}
	if actualCents > 0 {
		metricSpentCents.Add(float64(actualCents))
	}
	return nil
}

// RecordActual is kept for backward compat but delegates to Adjust(0, actualCents).
func (s *Service) RecordActual(ctx context.Context, orgID string, actualCents int64) error {
	return s.Adjust(ctx, orgID, 0, actualCents)
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

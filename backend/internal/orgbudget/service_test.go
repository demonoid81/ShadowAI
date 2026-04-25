//go:build enterprise

package orgbudget

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/shadowai/backend/internal/domain"
)

// ---------------------------------------------------------------------------
// In-memory repository mock
// ---------------------------------------------------------------------------

type memRepo struct {
	policy *domain.OrgBudgetPolicy
	usage  *domain.OrgBudgetUsage
	addErr error
}

func (m *memRepo) GetPolicy(_ context.Context, _ string) (*domain.OrgBudgetPolicy, error) {
	return m.policy, nil
}
func (m *memRepo) UpsertPolicy(_ context.Context, p *domain.OrgBudgetPolicy) error {
	m.policy = p
	return nil
}
func (m *memRepo) GetCurrentUsage(_ context.Context, orgID string) (*domain.OrgBudgetUsage, error) {
	if m.usage != nil {
		return m.usage, nil
	}
	return &domain.OrgBudgetUsage{OrgID: orgID}, nil
}
func (m *memRepo) AddSpend(_ context.Context, _ string, _ int64) error { return m.addErr }
func (m *memRepo) OrgExists(_ context.Context, _ string) (bool, error) { return true, nil }
func (m *memRepo) AtomicCheckAndAdd(_ context.Context, orgID string, estimatedCents, limitCents int64, enforce bool) (int64, bool, error) {
	current := int64(0)
	if m.usage != nil {
		current = m.usage.SpentCents
	}
	projected := current + estimatedCents
	if enforce && limitCents > 0 && projected >= limitCents {
		return current, false, nil
	}
	// Simulate reserve: update in-memory usage.
	if m.usage == nil {
		m.usage = &domain.OrgBudgetUsage{OrgID: orgID}
	}
	m.usage.SpentCents = projected
	return projected, true, nil
}

func newSvc(r *memRepo) *Service {
	return NewService(r, nil)
}

// ---------------------------------------------------------------------------
// Tests: CheckBefore modes
// ---------------------------------------------------------------------------

func TestOrgBudget_Disabled_AlwaysAllows(t *testing.T) {
	svc := newSvc(&memRepo{policy: nil}) // no policy = disabled
	dec, err := svc.CheckBefore(context.Background(), "org-1", 1000)
	if err != nil || !dec.Allowed {
		t.Errorf("disabled: want Allowed=true, got %+v err=%v", dec, err)
	}
}

func TestOrgBudget_Enforce_AllowsUnderCap(t *testing.T) {
	svc := newSvc(&memRepo{
		policy: &domain.OrgBudgetPolicy{
			OrgID: "org-1", Mode: domain.OrgBudgetEnforce, MonthlyLimitCents: 10000,
		},
		usage: &domain.OrgBudgetUsage{OrgID: "org-1", SpentCents: 5000},
	})
	dec, err := svc.CheckBefore(context.Background(), "org-1", 1000) // 5000+1000 < 10000
	if err != nil || !dec.Allowed {
		t.Errorf("enforce under cap: want Allowed=true, got %+v", dec)
	}
	if dec.Remaining != 4000 { // 10000 - (5000+1000)
		t.Errorf("remaining = %d, want 4000", dec.Remaining)
	}
}

func TestOrgBudget_Enforce_BlocksAtCap(t *testing.T) {
	svc := newSvc(&memRepo{
		policy: &domain.OrgBudgetPolicy{
			OrgID: "org-1", Mode: domain.OrgBudgetEnforce, MonthlyLimitCents: 10000,
		},
		usage: &domain.OrgBudgetUsage{OrgID: "org-1", SpentCents: 9500},
	})
	dec, err := svc.CheckBefore(context.Background(), "org-1", 600) // 9500+600 >= 10000
	if err != nil || dec.Allowed {
		t.Errorf("enforce at cap: want Allowed=false, got %+v err=%v", dec, err)
	}
	if dec.Mode != domain.OrgBudgetEnforce {
		t.Errorf("mode = %q, want enforce", dec.Mode)
	}
}

func TestOrgBudget_Observe_NeverBlocks(t *testing.T) {
	svc := newSvc(&memRepo{
		policy: &domain.OrgBudgetPolicy{
			OrgID: "org-1", Mode: domain.OrgBudgetObserve, MonthlyLimitCents: 1000,
		},
		usage: &domain.OrgBudgetUsage{OrgID: "org-1", SpentCents: 999},
	})
	dec, err := svc.CheckBefore(context.Background(), "org-1", 500) // over cap but observe
	if err != nil || !dec.Allowed {
		t.Errorf("observe over cap: want Allowed=true, got %+v", dec)
	}
}

func TestOrgBudget_Enforce_ZeroLimit_NeverBlocks(t *testing.T) {
	svc := newSvc(&memRepo{
		policy: &domain.OrgBudgetPolicy{
			OrgID: "org-1", Mode: domain.OrgBudgetEnforce, MonthlyLimitCents: 0, // unlimited
		},
		usage: &domain.OrgBudgetUsage{OrgID: "org-1", SpentCents: 1_000_000},
	})
	dec, err := svc.CheckBefore(context.Background(), "org-1", 1_000_000)
	if err != nil || !dec.Allowed {
		t.Errorf("zero limit = unlimited: want Allowed=true, got %+v", dec)
	}
}

func TestOrgBudget_EmptyOrgID_AlwaysAllows(t *testing.T) {
	svc := newSvc(&memRepo{})
	dec, err := svc.CheckBefore(context.Background(), "", 9999)
	if err != nil || !dec.Allowed {
		t.Errorf("empty org: want Allowed=true")
	}
}

func TestOrgBudget_RecordActual_ZeroNoop(t *testing.T) {
	repo := &memRepo{}
	svc := newSvc(repo)
	if err := svc.RecordActual(context.Background(), "org-1", 0); err != nil {
		t.Errorf("zero delta: unexpected err %v", err)
	}
}

func TestOrgBudget_RecordActual_PropagatesError(t *testing.T) {
	boom := errors.New("db down")
	repo := &memRepo{addErr: boom}
	svc := newSvc(repo)
	err := svc.RecordActual(context.Background(), "org-1", 100)
	if !errors.Is(err, boom) {
		t.Errorf("expected wrapped boom, got %v", err)
	}
}

func TestOrgBudget_FailOpen_OnPolicyError(t *testing.T) {
	// If GetPolicy returns an error, CheckBefore must allow (fail-open).
	svc := &Service{repo: &errRepo{}, adminAudit: nil}
	dec, err := svc.CheckBefore(context.Background(), "org-1", 1000)
	if err != nil || !dec.Allowed {
		t.Errorf("fail-open: want Allowed=true, got %+v err=%v", dec, err)
	}
}

// errRepo simulates a DB error on GetPolicy.
type errRepo struct{}

func (e *errRepo) GetPolicy(_ context.Context, _ string) (*domain.OrgBudgetPolicy, error) {
	return nil, errors.New("db error")
}
func (e *errRepo) UpsertPolicy(_ context.Context, _ *domain.OrgBudgetPolicy) error {
	return nil
}
func (e *errRepo) GetCurrentUsage(_ context.Context, orgID string) (*domain.OrgBudgetUsage, error) {
	return nil, sql.ErrNoRows
}
func (e *errRepo) AddSpend(_ context.Context, _ string, _ int64) error { return nil }
func (e *errRepo) OrgExists(_ context.Context, _ string) (bool, error)  { return true, nil }
func (e *errRepo) AtomicCheckAndAdd(_ context.Context, _ string, _, _ int64, _ bool) (int64, bool, error) {
	return 0, false, errors.New("db error")
}

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
func (m *memRepo) AddSpend(_ context.Context, _ string, delta int64) error {
	if m.addErr != nil {
		return m.addErr
	}
	if m.usage != nil {
		m.usage.SpentCents += delta
	}
	return nil
}
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

// ---------------------------------------------------------------------------
// Tests: Adjust truth table
// ---------------------------------------------------------------------------

func TestOrgBudget_Adjust_FinalizeReducesToActual(t *testing.T) {
	repo := &memRepo{usage: &domain.OrgBudgetUsage{OrgID: "org", SpentCents: 100}}
	svc := newSvc(repo)
	// reserved=60 actual=40 → delta = 40-60 = -20 → usage drops to 80
	if err := svc.Adjust(context.Background(), "org", 60, 40); err != nil {
		t.Fatalf("Adjust: %v", err)
	}
	if repo.usage.SpentCents != 80 {
		t.Errorf("after adjust usage=%d, want 80", repo.usage.SpentCents)
	}
}

func TestOrgBudget_Adjust_Refund_ZeroActual(t *testing.T) {
	repo := &memRepo{usage: &domain.OrgBudgetUsage{OrgID: "org", SpentCents: 100}}
	svc := newSvc(repo)
	// reserved=60 actual=0 → delta = -60 → usage drops to 40
	if err := svc.Adjust(context.Background(), "org", 60, 0); err != nil {
		t.Fatalf("Adjust refund: %v", err)
	}
	if repo.usage.SpentCents != 40 {
		t.Errorf("after refund usage=%d, want 40", repo.usage.SpentCents)
	}
}

func TestOrgBudget_Adjust_ObserveNoReservation(t *testing.T) {
	repo := &memRepo{usage: &domain.OrgBudgetUsage{OrgID: "org", SpentCents: 0}}
	svc := newSvc(repo)
	// reserved=0 actual=50 → delta=50 (observe mode records actual spend)
	if err := svc.Adjust(context.Background(), "org", 0, 50); err != nil {
		t.Fatalf("Adjust observe: %v", err)
	}
	if repo.usage.SpentCents != 50 {
		t.Errorf("observe usage=%d, want 50", repo.usage.SpentCents)
	}
}

func TestOrgBudget_Adjust_NoOpWhenBothZero(t *testing.T) {
	repo := &memRepo{usage: &domain.OrgBudgetUsage{OrgID: "org", SpentCents: 100}}
	svc := newSvc(repo)
	if err := svc.Adjust(context.Background(), "org", 0, 0); err != nil {
		t.Fatalf("Adjust noop: %v", err)
	}
	if repo.usage.SpentCents != 100 {
		t.Errorf("noop changed usage to %d, want 100", repo.usage.SpentCents)
	}
}

func TestOrgBudget_Adjust_NoOpOnEmptyOrg(t *testing.T) {
	svc := newSvc(&memRepo{})
	if err := svc.Adjust(context.Background(), "", 10, 5); err != nil {
		t.Errorf("empty org: unexpected err %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: mode semantics — disabled / observe / enforce
// ---------------------------------------------------------------------------

// TestOrgBudget_Disabled_AllowsNoReservation: disabled never blocks and does
// not reserve (ReservedCents=0). Actual spend IS still collected via
// Adjust(0, actual) — safe rollout baseline collection.
func TestOrgBudget_Disabled_AllowsNoReservation(t *testing.T) {
	svc := newSvc(&memRepo{policy: nil}) // nil policy = disabled
	dec, err := svc.CheckBefore(context.Background(), "org-1", 5000)
	if err != nil || !dec.Allowed {
		t.Fatalf("disabled: want Allowed=true, got %+v err=%v", dec, err)
	}
	if dec.Mode != domain.OrgBudgetDisabled {
		t.Errorf("mode = %q, want disabled", dec.Mode)
	}
	if dec.ReservedCents != 0 {
		t.Errorf("disabled should not reserve: ReservedCents=%d, want 0", dec.ReservedCents)
	}
}

// TestOrgBudget_Disabled_ActualSpendRecorded: Adjust(0, actual) writes spend
// for disabled mode — enables operators to collect baseline before enforcing.
func TestOrgBudget_Disabled_ActualSpendRecorded(t *testing.T) {
	repo := &memRepo{
		policy: &domain.OrgBudgetPolicy{OrgID: "org-1", Mode: domain.OrgBudgetDisabled},
		usage:  &domain.OrgBudgetUsage{OrgID: "org-1", SpentCents: 0},
	}
	svc := newSvc(repo)
	dec, _ := svc.CheckBefore(context.Background(), "org-1", 100)
	if !dec.Allowed || dec.ReservedCents != 0 {
		t.Fatalf("disabled pre-check: %+v", dec)
	}
	// Proxy calls Adjust(0, actual) after successful provider response.
	if err := svc.Adjust(context.Background(), "org-1", dec.ReservedCents, 80); err != nil {
		t.Fatalf("Adjust disabled: %v", err)
	}
	if repo.usage.SpentCents != 80 {
		t.Errorf("disabled: actual spend=%d, want 80", repo.usage.SpentCents)
	}
}

// TestOrgBudget_Observe_RecordsSpend: observe never blocks; Adjust(0, actual)
// writes actual spend (same mechanism as disabled, but emits soft-exceeded signal).
func TestOrgBudget_Observe_RecordsSpend(t *testing.T) {
	repo := &memRepo{
		policy: &domain.OrgBudgetPolicy{OrgID: "org-1", Mode: domain.OrgBudgetObserve, MonthlyLimitCents: 100},
		usage:  &domain.OrgBudgetUsage{OrgID: "org-1", SpentCents: 0},
	}
	svc := newSvc(repo)
	dec, _ := svc.CheckBefore(context.Background(), "org-1", 200) // over cap but observe
	if !dec.Allowed || dec.ReservedCents != 0 {
		t.Fatalf("observe: should be allowed and no reservation: %+v", dec)
	}
	if err := svc.Adjust(context.Background(), "org-1", 0, 150); err != nil {
		t.Fatalf("Adjust observe: %v", err)
	}
	if repo.usage.SpentCents != 150 {
		t.Errorf("observe: actual spend=%d, want 150", repo.usage.SpentCents)
	}
}

// TestOrgBudget_Enforce_FinalizeAndRefund: full enforce contract.
func TestOrgBudget_Enforce_FinalizeAndRefund(t *testing.T) {
	repo := &memRepo{
		policy: &domain.OrgBudgetPolicy{OrgID: "org-1", Mode: domain.OrgBudgetEnforce, MonthlyLimitCents: 1000},
		usage:  &domain.OrgBudgetUsage{OrgID: "org-1", SpentCents: 0},
	}
	svc := newSvc(repo)

	dec, _ := svc.CheckBefore(context.Background(), "org-1", 200)
	if !dec.Allowed || dec.ReservedCents != 200 {
		t.Fatalf("enforce: want reserved=200, got %+v", dec)
	}
	if repo.usage.SpentCents != 200 {
		t.Errorf("post-CheckBefore usage=%d, want 200 (reserved)", repo.usage.SpentCents)
	}
	// Provider succeeds: finalize actual=150 → delta=-50 → usage=150.
	svc.Adjust(context.Background(), "org-1", dec.ReservedCents, 150)
	if repo.usage.SpentCents != 150 {
		t.Errorf("post-finalize usage=%d, want 150", repo.usage.SpentCents)
	}
	// Second request: reserve 200 again, then provider fails → refund → usage=150.
	dec2, _ := svc.CheckBefore(context.Background(), "org-1", 200)
	svc.Adjust(context.Background(), "org-1", dec2.ReservedCents, 0)
	if repo.usage.SpentCents != 150 {
		t.Errorf("post-refund usage=%d, want 150", repo.usage.SpentCents)
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

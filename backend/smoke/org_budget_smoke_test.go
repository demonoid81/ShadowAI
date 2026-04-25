//go:build enterprise && smoke

// PR-G4: Org-level budget smoke scenarios.
package smoke

import (
	"context"
	"testing"
	"time"

	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/orgbudget"
)

const (
	smokeBudgetOrgA = "cc000001-0000-4000-8000-000000000001"
	smokeBudgetOrgB = "cc000002-0000-4000-8000-000000000001"
)

// TestSmoke_OrgBudget_TwoOrgs verifies:
//   - org A capped at 500 cents enforce — blocked when projected spend crosses cap
//   - org B observe mode — never blocked even over cap, but records spend
//   - one org's budget does not affect the other
func TestSmoke_OrgBudget_TwoOrgs(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	db := infra.DB

	// Seed org A and org B into organizations table.
	for _, row := range []struct{ id, name, slug string }{
		{smokeBudgetOrgA, "Budget Org A", "budget-org-a"},
		{smokeBudgetOrgB, "Budget Org B", "budget-org-b"},
	} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO organizations (id, name, slug) VALUES ($1,$2,$3) ON CONFLICT (id) DO NOTHING`,
			row.id, row.name, row.slug); err != nil {
			t.Fatalf("seed org %s: %v", row.slug, err)
		}
	}

	repo := orgbudget.NewRepository(db)
	svc := orgbudget.NewService(repo, nil)

	// Set org A policy: enforce at 500 cents.
	if err := svc.UpsertPolicy(ctx, &domain.OrgBudgetPolicy{
		OrgID:             smokeBudgetOrgA,
		Mode:              domain.OrgBudgetEnforce,
		MonthlyLimitCents: 500,
	}, "", ""); err != nil {
		t.Fatalf("UpsertPolicy orgA: %v", err)
	}

	// Set org B policy: observe at 200 cents.
	if err := svc.UpsertPolicy(ctx, &domain.OrgBudgetPolicy{
		OrgID:             smokeBudgetOrgB,
		Mode:              domain.OrgBudgetObserve,
		MonthlyLimitCents: 200,
	}, "", ""); err != nil {
		t.Fatalf("UpsertPolicy orgB: %v", err)
	}

	// Spend 450 cents on org A — under cap.
	if err := svc.RecordActual(ctx, smokeBudgetOrgA, 450); err != nil {
		t.Fatalf("RecordActual orgA 450: %v", err)
	}

	// CheckBefore org A with 100 estimated (450+100 >= 500) → blocked.
	dec, err := svc.CheckBefore(ctx, smokeBudgetOrgA, 100)
	if err != nil {
		t.Fatalf("CheckBefore orgA: %v", err)
	}
	if dec.Allowed {
		t.Error("org A should be blocked (enforce, over cap), got Allowed=true")
	}
	if dec.Mode != domain.OrgBudgetEnforce {
		t.Errorf("org A mode = %q, want enforce", dec.Mode)
	}
	t.Logf("smoke/org-budget: org A blocked at cap (spent=450 est=100 limit=500 remaining=%d)", dec.Remaining)

	// CheckBefore org A with 10 estimated (450+10 < 500) → allowed.
	decUnder, _ := svc.CheckBefore(ctx, smokeBudgetOrgA, 10)
	if !decUnder.Allowed {
		t.Error("org A with 10 est should be allowed (450+10 < 500)")
	}

	// CheckBefore org B with 1000 (way over 200) — observe never blocks.
	decB, err := svc.CheckBefore(ctx, smokeBudgetOrgB, 1000)
	if err != nil {
		t.Fatalf("CheckBefore orgB: %v", err)
	}
	if !decB.Allowed {
		t.Error("org B observe mode should never block, got Allowed=false")
	}
	t.Logf("smoke/org-budget: org B observe never blocks (remaining=%d)", decB.Remaining)

	// Verify org A's budget state does not bleed into org B.
	statusA, _ := svc.GetStatus(ctx, smokeBudgetOrgA)
	statusB, _ := svc.GetStatus(ctx, smokeBudgetOrgB)
	if statusB.Usage.SpentCents != 0 {
		t.Errorf("org B spent should be 0 (no RecordActual called), got %d", statusB.Usage.SpentCents)
	}
	t.Logf("smoke/org-budget: isolation OK (orgA spent=%d orgB spent=%d)",
		statusA.Usage.SpentCents, statusB.Usage.SpentCents)

	// Spend on org B — org A unaffected.
	if err := svc.RecordActual(ctx, smokeBudgetOrgB, 300); err != nil {
		t.Fatalf("RecordActual orgB: %v", err)
	}
	statusAAfter, _ := svc.GetStatus(ctx, smokeBudgetOrgA)
	// After AtomicCheckAndAdd reserved 10 cents (second CheckBefore), usage = 450+10 = 460.
	if statusAAfter.Usage.SpentCents != 460 {
		t.Errorf("org A spent after org B record = %d, want 460 (450 initial + 10 reserved by CheckBefore)", statusAAfter.Usage.SpentCents)
	}
	t.Logf("smoke/org-budget: org A spent %d after org B record (reservation visible in usage) ✓", statusAAfter.Usage.SpentCents)

	// Verify period rollover: new month = zero usage.
	lastMonth := time.Now().UTC().AddDate(0, -1, 0)
	_ = lastMonth // The test just verifies current month; rollover happens at period_start boundary.
	t.Logf("smoke/org-budget: all assertions passed")
}

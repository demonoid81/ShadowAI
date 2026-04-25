//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// PR-G4: org-level aggregate budget repository.

package orgbudget

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/shadowai/backend/internal/domain"
)

// Repository handles org_budget_policies and org_budget_usage tables.
type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// GetPolicy reads the org's budget policy. Returns (nil, nil) when no policy exists.
func (r *Repository) GetPolicy(ctx context.Context, orgID string) (*domain.OrgBudgetPolicy, error) {
	var p domain.OrgBudgetPolicy
	var updatedBy sql.NullString
	err := r.db.QueryRowContext(ctx,
		`SELECT org_id, monthly_limit_cents, mode, updated_at, updated_by
		 FROM org_budget_policies WHERE org_id = $1`, orgID).
		Scan(&p.OrgID, &p.MonthlyLimitCents, &p.Mode, &p.UpdatedAt, &updatedBy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get org budget policy: %w", err)
	}
	if updatedBy.Valid {
		s := updatedBy.String
		p.UpdatedBy = &s
	}
	return &p, nil
}

// UpsertPolicy inserts or updates the org's budget policy.
func (r *Repository) UpsertPolicy(ctx context.Context, p *domain.OrgBudgetPolicy) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO org_budget_policies (org_id, monthly_limit_cents, mode, updated_at, updated_by)
		 VALUES ($1, $2, $3, now(), $4)
		 ON CONFLICT (org_id) DO UPDATE
		   SET monthly_limit_cents = EXCLUDED.monthly_limit_cents,
		       mode = EXCLUDED.mode,
		       updated_at = now(),
		       updated_by = EXCLUDED.updated_by`,
		p.OrgID, p.MonthlyLimitCents, string(p.Mode), nullableStr(p.UpdatedBy))
	return err
}

// GetCurrentUsage returns spend for the current calendar month.
// Returns a zero-value record when no row exists yet for this period.
func (r *Repository) GetCurrentUsage(ctx context.Context, orgID string) (*domain.OrgBudgetUsage, error) {
	period := currentPeriod()
	var u domain.OrgBudgetUsage
	err := r.db.QueryRowContext(ctx,
		`SELECT org_id, period_start, spent_cents
		 FROM org_budget_usage WHERE org_id = $1 AND period_start = $2`,
		orgID, period).Scan(&u.OrgID, &u.PeriodStart, &u.SpentCents)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &domain.OrgBudgetUsage{OrgID: orgID, PeriodStart: period}, nil
		}
		return nil, fmt.Errorf("get org budget usage: %w", err)
	}
	return &u, nil
}

// AddSpend atomically increments the org's current-month spend.
// Creates the row on first use (UPSERT).
func (r *Repository) AddSpend(ctx context.Context, orgID string, deltaCents int64) error {
	if deltaCents == 0 {
		return nil
	}
	period := currentPeriod()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO org_budget_usage (org_id, period_start, spent_cents)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (org_id, period_start)
		 DO UPDATE SET spent_cents = org_budget_usage.spent_cents + EXCLUDED.spent_cents`,
		orgID, period, deltaCents)
	return err
}

// OrgExists returns true when the organizations table has a row with this id.
func (r *Repository) OrgExists(ctx context.Context, orgID string) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1)`, orgID).Scan(&exists)
	return exists, err
}

// AtomicCheckAndAdd serializes concurrent budget checks for the same org via
// a session-level PostgreSQL advisory lock (hashtext of orgID). In a single
// transaction it:
//   1. Acquires the advisory lock for this org.
//   2. Reads the current usage for the current period.
//   3. Evaluates the cap (limitCents=0 = unlimited; enforce=false = observe/allow).
//   4. If allowed: UPSERTs usage += estimatedCents and returns (spentAfter, true, nil).
//   5. If blocked: returns (currentSpent, false, nil) without modifying usage.
//
// Callers must call AddSpend(orgID, actualCents-estimatedCents) afterwards to
// adjust the reservation to the real cost (negative delta refunds the unused reserve).
func (r *Repository) AtomicCheckAndAdd(ctx context.Context, orgID string, estimatedCents, limitCents int64, enforce bool) (spentAfter int64, allowed bool, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("orgbudget: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Advisory lock serializes concurrent CheckBefore calls for this org.
	// hashtext() maps the UUID string to int32 safely.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(abs(hashtext($1)))`, orgID); err != nil {
		return 0, false, fmt.Errorf("orgbudget: advisory lock: %w", err)
	}

	period := currentPeriod()
	var currentSpent int64
	err = tx.QueryRowContext(ctx,
		`SELECT COALESCE(spent_cents, 0) FROM org_budget_usage
		 WHERE org_id = $1 AND period_start = $2`, orgID, period).Scan(&currentSpent)
	if err != nil && err != sql.ErrNoRows {
		return 0, false, fmt.Errorf("orgbudget: read usage: %w", err)
	}
	// sql.ErrNoRows means no usage yet this month → currentSpent = 0 (already set).

	projected := currentSpent + estimatedCents
	if enforce && limitCents > 0 && projected >= limitCents {
		return currentSpent, false, tx.Commit()
	}

	// Reserve estimated spend.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO org_budget_usage (org_id, period_start, spent_cents)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (org_id, period_start)
		 DO UPDATE SET spent_cents = org_budget_usage.spent_cents + EXCLUDED.spent_cents`,
		orgID, period, estimatedCents); err != nil {
		return 0, false, fmt.Errorf("orgbudget: reserve: %w", err)
	}
	return projected, true, tx.Commit()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func currentPeriod() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func nullableStr(s *string) any {
	if s == nil || *s == "" {
		return nil
	}
	return *s
}

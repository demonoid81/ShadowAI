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

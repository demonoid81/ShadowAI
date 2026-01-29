package budget

import (
	"context"
	"database/sql"
	"github.com/shadowai/backend/internal/domain"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) GetByUserID(ctx context.Context, userID string) (*domain.Budget, error) {
	var b domain.Budget
	err := r.db.QueryRowContext(ctx,
		`SELECT id, user_id, monthly_limit_usd, monthly_spent_usd, monthly_token_limit, monthly_tokens_used, period_start
		FROM budgets WHERE user_id = $1`, userID).
		Scan(&b.ID, &b.UserID, &b.MonthlyLimitUSD, &b.MonthlySpentUSD, &b.MonthlyTokenLimit, &b.MonthlyTokensUsed, &b.PeriodStart)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func (r *Repository) Upsert(ctx context.Context, b *domain.Budget) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO budgets (id, user_id, monthly_limit_usd, monthly_spent_usd, monthly_token_limit, monthly_tokens_used, period_start)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (user_id) DO UPDATE SET monthly_limit_usd=$3, monthly_spent_usd=$4, monthly_token_limit=$5, monthly_tokens_used=$6, period_start=$7`,
		b.ID, b.UserID, b.MonthlyLimitUSD, b.MonthlySpentUSD, b.MonthlyTokenLimit, b.MonthlyTokensUsed, b.PeriodStart)
	return err
}

func (r *Repository) UpdateSpent(ctx context.Context, userID string, addCost float64, addTokens int) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE budgets SET monthly_spent_usd = monthly_spent_usd + $1, monthly_tokens_used = monthly_tokens_used + $2 WHERE user_id = $3`,
		addCost, addTokens, userID)
	return err
}

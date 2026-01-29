package domain

import "time"

type Budget struct {
	ID                string    `json:"id"`
	UserID            string    `json:"user_id"`
	MonthlyLimitUSD   float64   `json:"monthly_limit_usd"`
	MonthlySpentUSD   float64   `json:"monthly_spent_usd"`
	MonthlyTokenLimit int       `json:"monthly_token_limit"`
	MonthlyTokensUsed int       `json:"monthly_tokens_used"`
	PeriodStart       time.Time `json:"period_start"`
}

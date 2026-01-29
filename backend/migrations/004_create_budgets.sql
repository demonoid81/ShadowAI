CREATE TABLE IF NOT EXISTS budgets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES users(id),
    monthly_limit_usd NUMERIC(10,2) NOT NULL DEFAULT 100.00,
    monthly_spent_usd NUMERIC(10,6) NOT NULL DEFAULT 0,
    monthly_token_limit INT NOT NULL DEFAULT 1000000,
    monthly_tokens_used INT NOT NULL DEFAULT 0,
    period_start DATE NOT NULL DEFAULT date_trunc('month', CURRENT_DATE)
);

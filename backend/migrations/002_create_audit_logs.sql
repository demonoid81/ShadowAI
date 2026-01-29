CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    request_body TEXT,
    response_body TEXT,
    model VARCHAR(100),
    provider VARCHAR(50) DEFAULT 'openai',
    endpoint VARCHAR(255),
    status_code INT,
    prompt_tokens INT DEFAULT 0,
    completion_tokens INT DEFAULT 0,
    total_tokens INT DEFAULT 0,
    cost_usd NUMERIC(10,6) DEFAULT 0,
    pii_detected BOOLEAN DEFAULT false,
    pii_types TEXT[],
    policy_action VARCHAR(20) DEFAULT 'allowed',
    duration_ms INT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);

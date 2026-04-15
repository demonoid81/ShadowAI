-- Seed admin user (password: admin123)
INSERT INTO users (id, email, password, role, api_key, is_active)
VALUES (
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    'admin@shadowai.local',
    '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
    '2af8a7d16cf91ee4ca8f7765e147c98a33b7f5d32fdfcf0e6cabf4f5ada370a1',
    true
) ON CONFLICT (email) DO NOTHING;

-- Seeded API key (plain): sk-shadow-admin-0000000000000000000000000000000000000000

-- Seed default policies
INSERT INTO policy_rules (id, name, rule_type, config, is_active, priority) VALUES
(
    'b0eebc99-9c0b-4ef8-bb6d-6bb9bd380b01',
    'Block PII: Credit Cards & SSN',
    'pii_block',
    '{"pii_types": ["credit_card", "ssn"]}',
    true,
    1
),
(
    'b0eebc99-9c0b-4ef8-bb6d-6bb9bd380b02',
    'Warn on Email/Phone PII',
    'pii_warn',
    '{"pii_types": ["email", "phone"]}',
    true,
    2
),
(
    'b0eebc99-9c0b-4ef8-bb6d-6bb9bd380b03',
    'Block harmful keywords',
    'keyword_block',
    '{"keywords": ["ignore previous instructions", "jailbreak", "DAN mode"]}',
    true,
    3
)
ON CONFLICT DO NOTHING;

-- Seed budget for admin
INSERT INTO budgets (id, user_id, monthly_limit_usd, monthly_token_limit, period_start)
VALUES (
    'c0eebc99-9c0b-4ef8-bb6d-6bb9bd380c01',
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    100.00,
    1000000,
    date_trunc('month', CURRENT_DATE)
) ON CONFLICT (user_id) DO NOTHING;

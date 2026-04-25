-- PR-G4: Org-level aggregate budget caps.
--
-- org_budget_policies: one row per org (upsert-based).
--   mode: disabled|observe|enforce (default disabled = no cap).
--   monthly_limit_cents: 0 means unlimited even in enforce mode.
--
-- org_budget_usage: append-only monthly accumulator.
--   PK = (org_id, period_start) so month rollover = new row.
--   spent_cents updated atomically via UPDATE ... SET spent_cents = spent_cents + $delta.
--
-- Depends on: migrations/018_tenant_schema_seed.sql (organizations table).

CREATE TABLE IF NOT EXISTS org_budget_policies (
    org_id              UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE RESTRICT,
    monthly_limit_cents BIGINT NOT NULL DEFAULT 0
                            CHECK (monthly_limit_cents >= 0),
    -- mode: disabled = no org-level check; observe = record but never block;
    -- enforce = block when projected spend >= cap.
    mode                VARCHAR(16) NOT NULL DEFAULT 'disabled'
                            CHECK (mode IN ('disabled','observe','enforce')),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by          UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_org_budget_policies_mode
    ON org_budget_policies (mode);

CREATE TABLE IF NOT EXISTS org_budget_usage (
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    period_start DATE NOT NULL,
    spent_cents  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (org_id, period_start)
);

CREATE INDEX IF NOT EXISTS idx_org_budget_usage_org_period
    ON org_budget_usage (org_id, period_start DESC);

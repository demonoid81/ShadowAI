-- PR-T2.1: Tenant schema seed (enterprise).
--
-- Зависит от: core migration 018 (organizations table должна существовать).
-- Применяется ПОСЛЕ backend/migrations/018_tenant_schema_seed.sql.
--
-- Добавляет org_id во все enterprise tenant-scoped таблицы.
-- Добавляет source_org_id/target_org_id/canonical_version в admin_event_logs
-- (cross-tenant audit evidence — first-class columns, не metadata_json, RFC D2/D3).
-- Создаёт scim_tokens — org-scoped Bearer token registry (RFC D6.1).
--
-- Не затрагивает:
--   - singleton constraint idx_gov_policy_singleton_active: остаётся global.
--     Unique-per-org constraint добавляется в отдельном PR после Phase 4.
--   - chain fields (seq_no, row_hash): уже добавлены в migration 016.
--
-- RFC: docs/rfcs/2026-04-pr-t1-tenant-isolation.md §D2, §D3, §D6

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. user_erasure_runs.org_id
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE user_erasure_runs
    ADD COLUMN IF NOT EXISTS org_id UUID NOT NULL
        DEFAULT '00000000-0000-0000-0000-000000000001'
        REFERENCES organizations(id);

CREATE INDEX IF NOT EXISTS idx_user_erasure_runs_org_id
    ON user_erasure_runs (org_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. admin_event_logs.org_id + source_org_id + target_org_id + canonical_version
--
-- source_org_id: org актора (actor's org).
-- target_org_id: org, на которую направлено действие (только cross-tenant).
--   NULL для same-org операций.
--   Nullable UUID, без FK: actor's org может быть global (org_id=""), а
--   target может существовать или нет. FK усложнил бы cleanup.
-- canonical_version: для будущего canonical v2 (org_id|source_org_id|target_org_id
--   входят в HMAC chain, RFC D3).
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE admin_event_logs
    ADD COLUMN IF NOT EXISTS org_id UUID NOT NULL
        DEFAULT '00000000-0000-0000-0000-000000000001'
        REFERENCES organizations(id),
    ADD COLUMN IF NOT EXISTS source_org_id UUID,
    ADD COLUMN IF NOT EXISTS target_org_id UUID,
    ADD COLUMN IF NOT EXISTS canonical_version VARCHAR(4) NOT NULL DEFAULT 'v1';

CREATE INDEX IF NOT EXISTS idx_admin_event_logs_org_created
    ON admin_event_logs (org_id, created_at DESC);

-- Индекс для cross-tenant audit queries (global_admin dashboard).
CREATE INDEX IF NOT EXISTS idx_admin_event_logs_target_org
    ON admin_event_logs (target_org_id)
    WHERE target_org_id IS NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'chk_admin_event_logs_canonical_version'
           AND conrelid = 'admin_event_logs'::regclass
    ) THEN
        ALTER TABLE admin_event_logs
            ADD CONSTRAINT chk_admin_event_logs_canonical_version
                CHECK (canonical_version IN ('v1', 'v2'));
    END IF;
END $$;

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. provider_governance_policies.org_id
--
-- Singleton constraint idx_gov_policy_singleton_active (is_active=true,
-- global) остаётся без изменений — один active policy глобально для T2.1.
-- Unique-per-org enforcement добавляется в Phase 4 отдельным PR.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE provider_governance_policies
    ADD COLUMN IF NOT EXISTS org_id UUID NOT NULL
        DEFAULT '00000000-0000-0000-0000-000000000001'
        REFERENCES organizations(id);

CREATE INDEX IF NOT EXISTS idx_gov_policies_org_id
    ON provider_governance_policies (org_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. legal_holds.org_id
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE legal_holds
    ADD COLUMN IF NOT EXISTS org_id UUID NOT NULL
        DEFAULT '00000000-0000-0000-0000-000000000001'
        REFERENCES organizations(id);

CREATE INDEX IF NOT EXISTS idx_legal_holds_org_id
    ON legal_holds (org_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- 5. legal_hold_events.org_id + canonical_version
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE legal_hold_events
    ADD COLUMN IF NOT EXISTS org_id UUID NOT NULL
        DEFAULT '00000000-0000-0000-0000-000000000001'
        REFERENCES organizations(id),
    ADD COLUMN IF NOT EXISTS canonical_version VARCHAR(4) NOT NULL DEFAULT 'v1';

CREATE INDEX IF NOT EXISTS idx_legal_hold_events_org_id
    ON legal_hold_events (org_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'chk_legal_hold_events_canonical_version'
           AND conrelid = 'legal_hold_events'::regclass
    ) THEN
        ALTER TABLE legal_hold_events
            ADD CONSTRAINT chk_legal_hold_events_canonical_version
                CHECK (canonical_version IN ('v1', 'v2'));
    END IF;
END $$;

-- ─────────────────────────────────────────────────────────────────────────────
-- 6. scim_tokens — org-scoped Bearer token registry (RFC D6.1)
--
-- Один token привязан к одному org_id. Middleware резолвит org из
-- token record; X-Org-ID header не используется.
-- token_hash хранит bcrypt/SHA-256 хэш bearer token (never plaintext).
-- is_active позволяет отзыв без удаления для audit trail.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scim_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES organizations(id),
    token_hash   VARCHAR(128) UNIQUE NOT NULL,
    label        VARCHAR(128),
    is_active    BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scim_tokens_org_active
    ON scim_tokens (org_id, is_active);

-- PR-T2.1: Tenant schema seed (core).
--
-- Additive-only: создаём organizations, добавляем org_id во все
-- tenant-scoped таблицы через ADD COLUMN … DEFAULT. Никаких DROP,
-- никаких breaking NOT NULL без DEFAULT.
--
-- Zero-downtime: ADD COLUMN NOT NULL DEFAULT — в PG 11+ это
-- instant metadata op (constant default), таблица не переписывается.
-- Существующие строки получают default при первом чтении.
--
-- Не затрагивает:
--   - budgets: изоляция через budgets.user_id → users.org_id JOIN (RFC D6.2).
--   - audit_chain_anchors: глобальная таблица без org (RFC D4).
--
-- Зависит от: ничего (первая tenant-migration).
-- После этой миграции enterprise-миграция 018 может ссылаться
-- на organizations через FK.
--
-- RFC: docs/rfcs/2026-04-pr-t1-tenant-isolation.md §D1, §D5, §D6

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. Organizations table + default org seed
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS organizations (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       VARCHAR(256) NOT NULL,
    slug       VARCHAR(128) UNIQUE NOT NULL,
    is_active  BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_organizations_slug
    ON organizations (slug);

-- Default org: стабильный UUID для single-tenant deployments.
-- ON CONFLICT идемпотентность (повторный запуск не ломает).
INSERT INTO organizations (id, name, slug)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default')
ON CONFLICT (id) DO NOTHING;

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. users.org_id
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS org_id UUID NOT NULL
        DEFAULT '00000000-0000-0000-0000-000000000001'
        REFERENCES organizations(id);

CREATE INDEX IF NOT EXISTS idx_users_org_id
    ON users (org_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. audit_logs.org_id + canonical_version
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS org_id UUID NOT NULL
        DEFAULT '00000000-0000-0000-0000-000000000001'
        REFERENCES organizations(id),
    ADD COLUMN IF NOT EXISTS canonical_version VARCHAR(4) NOT NULL DEFAULT 'v1';

CREATE INDEX IF NOT EXISTS idx_audit_logs_org_created
    ON audit_logs (org_id, created_at DESC);

-- canonical_version CHECK: idempotent добавление через DO block.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'chk_audit_logs_canonical_version'
           AND conrelid = 'audit_logs'::regclass
    ) THEN
        ALTER TABLE audit_logs
            ADD CONSTRAINT chk_audit_logs_canonical_version
                CHECK (canonical_version IN ('v1', 'v2'));
    END IF;
END $$;

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. policy_rules.org_id
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE policy_rules
    ADD COLUMN IF NOT EXISTS org_id UUID NOT NULL
        DEFAULT '00000000-0000-0000-0000-000000000001'
        REFERENCES organizations(id);

CREATE INDEX IF NOT EXISTS idx_policy_rules_org_id
    ON policy_rules (org_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- 5. internal_db_sources.org_id
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE internal_db_sources
    ADD COLUMN IF NOT EXISTS org_id UUID NOT NULL
        DEFAULT '00000000-0000-0000-0000-000000000001'
        REFERENCES organizations(id);

CREATE INDEX IF NOT EXISTS idx_internal_db_sources_org_id
    ON internal_db_sources (org_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- 6. audit_purge_runs.org_id + canonical_version + scope
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE audit_purge_runs
    ADD COLUMN IF NOT EXISTS org_id UUID NOT NULL
        DEFAULT '00000000-0000-0000-0000-000000000001'
        REFERENCES organizations(id),
    ADD COLUMN IF NOT EXISTS canonical_version VARCHAR(4) NOT NULL DEFAULT 'v1',
    ADD COLUMN IF NOT EXISTS scope VARCHAR(16) NOT NULL DEFAULT 'org';

CREATE INDEX IF NOT EXISTS idx_audit_purge_runs_org_started
    ON audit_purge_runs (org_id, started_at DESC);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'chk_audit_purge_runs_scope'
           AND conrelid = 'audit_purge_runs'::regclass
    ) THEN
        ALTER TABLE audit_purge_runs
            ADD CONSTRAINT chk_audit_purge_runs_scope
                CHECK (scope IN ('org', 'global'));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'chk_audit_purge_runs_canonical_version'
           AND conrelid = 'audit_purge_runs'::regclass
    ) THEN
        ALTER TABLE audit_purge_runs
            ADD CONSTRAINT chk_audit_purge_runs_canonical_version
                CHECK (canonical_version IN ('v1', 'v2'));
    END IF;
END $$;

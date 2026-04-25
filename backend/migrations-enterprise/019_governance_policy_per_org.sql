-- PR-T2.3: Governance policy per-org isolation.
--
-- Заменяет глобальный singleton-constraint на per-org unique:
--   - один active policy per org (not per deployment)
--   - DROP INDEX не поддерживает CONCURRENTLY — brief lock на таблице
--     (microseconds в single-org deploy, одна строка)
--
-- Зависит от: core 018 (organizations) и enterprise 018 (org_id column).
-- После этой миграции второй tenant сможет иметь свою active policy.

DROP INDEX IF EXISTS idx_gov_policy_singleton_active;

CREATE UNIQUE INDEX IF NOT EXISTS idx_gov_policy_active_per_org
    ON provider_governance_policies (org_id)
    WHERE is_active = true;

-- Быстрый lookup для GetActive(org_id).
CREATE INDEX IF NOT EXISTS idx_gov_policy_org_active_updated
    ON provider_governance_policies (org_id, updated_at DESC)
    WHERE is_active = true;

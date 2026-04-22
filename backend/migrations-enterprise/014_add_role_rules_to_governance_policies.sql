-- PR-G2: Role-based governance (enterprise, phase 2).
--
-- Добавляет role_rules_json к provider_governance_policies.
-- rules_json (PR-G1) оставлен без изменений — он применяется в
-- Mode=allowlist_strict. role_rules_json применяется в Mode=
-- role_based.
--
-- Shape role_rules_json (JSONB array):
--   [
--     {"role":"admin",   "rules":[{"provider":"openai","models":["gpt-4o"]}]},
--     {"role":"analyst", "rules":[{"provider":"openai","models":["gpt-4o-mini"]}]}
--   ]
--
-- Deny-by-default: если claims.Role отсутствует в role_rules,
-- Evaluate возвращает Deny (code=unknown_role). Это осознанная
-- enterprise policy — compliance-ориентированные deploy'ы хотят
-- чтобы operator явно описал права каждой роли.
ALTER TABLE provider_governance_policies
    ADD COLUMN IF NOT EXISTS role_rules_json JSONB NOT NULL DEFAULT '[]'::jsonb;

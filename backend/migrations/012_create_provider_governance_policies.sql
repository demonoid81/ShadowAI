-- PR-G1: Provider/Model Governance (phase 1).
--
-- Хранит активную governance-политику — allowlist провайдеров и
-- моделей внутри провайдера. Одна active политика за раз (singleton
-- в phase 1); многополисная модель придёт в PR-G2 (role-based).
--
-- Почему singleton сейчас:
--   - scope PR-G1 зафиксирован (allowlist + deny-by-default +
--     visibility) — не включает role-based routing;
--   - singleton снимает вопросы «какая политика применяется к какому
--     запросу»: всегда одна;
--   - в PR-G2 мы расширим модель (несколько политик + role matrix),
--     и singleton-constraint снимется partial-index'ом на role_id.
--
-- Rules хранятся в JSONB для гибкости (список provider-рулов
-- переменной длины). Evaluate читает всю active policy одним запросом
-- и решает логику в памяти — per-request overhead минимален.
CREATE TABLE IF NOT EXISTS provider_governance_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- name — человекочитаемый ярлык политики. В singleton-режиме
    -- обычно "default". В PR-G2 — имя roles scope'а.
    name VARCHAR(128) NOT NULL DEFAULT 'default',

    -- mode: 'disabled' (governance выключен, но политика сохранена
    -- для quick re-enable) | 'allowlist_strict' (deny-by-default).
    -- См. governance.Mode в Go-коде. Новые значения добавляются
    -- только вместе с backend-support (валидация в Mode.IsValid).
    mode VARCHAR(32) NOT NULL DEFAULT 'disabled',

    -- rules_json — JSON-массив ProviderRule:
    --   [{"provider":"openai","models":["gpt-4","gpt-4o-mini"]},
    --    {"provider":"anthropic","models":["claude-3-opus"]}]
    -- Пустой массив в сочетании с mode=allowlist_strict =
    -- deny-all (fail-closed).
    rules_json JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- Audit-trail: кто и когда последний раз менял политику.
    -- updated_by NULL для системных изменений (CLI/миграций).
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,

    -- is_active — singleton-flag. В phase 1 всегда true для
    -- единственной строки. Inactive политики могут храниться как
    -- "history" после superseded, если позже понадобится.
    is_active BOOLEAN NOT NULL DEFAULT true
);

-- Singleton-constraint для phase 1: ровно одна active политика.
-- PR-G2 снимет этот partial-unique и добавит scope-columns.
CREATE UNIQUE INDEX IF NOT EXISTS idx_gov_policy_singleton_active
    ON provider_governance_policies (is_active)
    WHERE is_active = true;

-- Индекс для быстрого чтения active policy в Evaluate (hot path).
CREATE INDEX IF NOT EXISTS idx_gov_policy_active_lookup
    ON provider_governance_policies (is_active, updated_at DESC);

-- Seed row: одна default-политика в mode=disabled. Это значит:
--   - свежий deploy → governance сконфигурирован, но неактивен;
--   - admin может через UI переключить mode в allowlist_strict
--     и добавить rules — и сразу получить deny-by-default.
--
-- Без seed-row handler GetPolicy возвращал бы 404 / пустой ответ,
-- что затрудняет first-use UX.
INSERT INTO provider_governance_policies (name, mode, rules_json, is_active)
SELECT 'default', 'disabled', '[]'::jsonb, true
WHERE NOT EXISTS (
    SELECT 1 FROM provider_governance_policies WHERE is_active = true
);

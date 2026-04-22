-- PR-L1: Legal hold groundwork (enterprise).
--
-- Блокирует DSAR/erasure для пользователей под judicial/regulatory
-- hold. GDPR "right to erasure" имеет явный carve-out для legal
-- obligations (Art.17(3)b/c/e), поэтому hold overrides erasure
-- request.
--
-- Жизненный цикл:
--   1) admin создаёт hold: apply_hold, is_active=true
--   2) EraseUser на этого user'а → 409 hold_active (DSAR
--      отвергнут; event erase + metadata.blocked_by_hold=true
--      в admin_event_logs)
--   3) admin снимает hold: release_hold, is_active=false,
--      released_at/released_by заполняются, row остаётся (audit
--      trail)
--   4) повторный erase после release → выполняется штатно
--
-- Почему is_active вместо is_released: позволяет позже расширить
-- status'ами (pending_release, archived) без миграции. На v1
-- is_active достаточно.
CREATE TABLE IF NOT EXISTS legal_holds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- target_user_id — user под hold'ом. ON DELETE RESTRICT:
    -- нельзя удалить user пока есть active hold. is_active=false
    -- row'ы могут остаться: история завершённых hold'ов для
    -- compliance-audit.
    target_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    -- case_ref — идентификатор судебного дела / regulatory request.
    -- Свободный текст (case number, subpoena ID, etc.).
    case_ref VARCHAR(255) NOT NULL,

    -- reason — why. Пример: "litigation XYZ", "CFPB inquiry 2026-04".
    reason TEXT NOT NULL,

    -- created_by: admin, инициировавший hold. ON DELETE SET NULL,
    -- чтобы удаление самого admin'а (если такое когда-либо
    -- случится) не сломало audit trail hold-ов.
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- released_at/released_by — заполняются при release_hold. NULL
    -- до release. На v1 release делает hold неактивным, сам row
    -- сохраняется.
    released_at TIMESTAMPTZ,
    released_by UUID REFERENCES users(id) ON DELETE SET NULL,

    is_active BOOLEAN NOT NULL DEFAULT true
);

-- Partial unique — максимум один active hold на user. Повторный
-- apply_hold на user'а уже под hold'ом → DB unique_violation,
-- handler мапит в 409 conflict.
CREATE UNIQUE INDEX IF NOT EXISTS idx_legal_holds_active_per_user
    ON legal_holds (target_user_id)
    WHERE is_active = true;

-- Быстрый lookup "есть ли active hold у user'а" (hot path для
-- EraseUser).
CREATE INDEX IF NOT EXISTS idx_legal_holds_active_lookup
    ON legal_holds (target_user_id, is_active);

-- Список всех hold-ов (active first, потом released).
CREATE INDEX IF NOT EXISTS idx_legal_holds_created_at
    ON legal_holds (created_at DESC);

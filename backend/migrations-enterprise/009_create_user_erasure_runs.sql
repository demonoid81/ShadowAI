-- PR-B: DSAR / Erasure Workflow.
--
-- Служебная таблица: хранит историю выполненных erasure-операций.
-- Используется для:
--   - идемпотентности (повторный запуск для уже erased user
--     возвращает "already_erased", не "not_found");
--   - compliance-trail (кто инициировал erase, когда, сколько
--     audit-строк было обезличено).
--
-- target_user_id НЕ FK на users: строки остаются после того, как
-- сам user удалён. Это осознанный дизайн — tombstone для будущих
-- запросов.
--
-- initiated_by_user_id — FK (admin, запустивший erase). Может
-- стать NULL если сам admin был потом erased.
CREATE TABLE IF NOT EXISTS user_erasure_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_user_id UUID NOT NULL,
    initiated_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    audit_rows_scrubbed INT NOT NULL DEFAULT 0,
    budgets_deleted INT NOT NULL DEFAULT 0,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_user_erasure_runs_target
    ON user_erasure_runs(target_user_id);
CREATE INDEX IF NOT EXISTS idx_user_erasure_runs_completed_at
    ON user_erasure_runs(completed_at DESC);

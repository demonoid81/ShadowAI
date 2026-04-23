-- PR-L2.3: 4-eyes approver workflow для legal hold.
--
-- Добавляет `status` column ('pending' | 'active' | 'released').
-- Poet contract:
--   - Create (POST /api/legal-holds) → status='pending'.
--     Ещё НЕ блокирует DSAR и НЕ защищает от purge.
--   - Approve (POST /api/legal-holds/{id}/approve) → pending → active.
--     Approver должен быть другим admin (не creator).
--   - Reject (POST /api/legal-holds/{id}/reject) → pending → released.
--   - Release (POST /api/legal-holds/{id}/release) → active → released.
--
-- `is_active` column сохраняется для backward compat и как
-- derivative от status ('active' ↔ true). Код пишет оба в sync.
--
-- Partial unique index меняется: было "один active per user",
-- стало "один блокирующий (pending или active) per user", чтобы
-- admin не мог создать второй pending поверх существующего.
ALTER TABLE legal_holds
    ADD COLUMN IF NOT EXISTS status VARCHAR(16) NOT NULL DEFAULT 'active';

-- Миграция данных: существующие released rows (is_active=false)
-- получают status='released'; active (is_active=true) уже
-- 'active' благодаря DEFAULT.
UPDATE legal_holds
   SET status = 'released'
 WHERE is_active = false AND status = 'active';

-- Заменяем старый partial-unique index на новый с расширенным
-- predicate'ом.
DROP INDEX IF EXISTS idx_legal_holds_active_per_user;
CREATE UNIQUE INDEX IF NOT EXISTS idx_legal_holds_blocking_per_user
    ON legal_holds (target_user_id)
    WHERE status IN ('pending', 'active');

-- Отдельный BT-индекс для HasActiveHold hot path (WHERE status='active').
CREATE INDEX IF NOT EXISTS idx_legal_holds_status_active
    ON legal_holds (target_user_id)
    WHERE status = 'active';

-- Approval audit-fields. Заполняются при approve.
ALTER TABLE legal_holds
    ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS approved_by UUID REFERENCES users(id) ON DELETE SET NULL;

-- Check-constraint на status values. Предотвращает direct-SQL
-- insert с неизвестным статусом.
ALTER TABLE legal_holds
    ADD CONSTRAINT legal_holds_status_check
    CHECK (status IN ('pending', 'active', 'released'));

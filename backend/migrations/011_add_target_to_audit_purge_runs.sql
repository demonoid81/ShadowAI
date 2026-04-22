-- PR-D.1: Admin-events retention (разные TTL для audit_logs и admin_event_logs).
--
-- Общая таблица audit_purge_runs теперь трекает purge-операции обоих
-- источников через новую колонку `target`. Существующие строки
-- (сгенерированные PR-A до этого PR) получат default 'audit_logs'.
--
-- Альтернатива — отдельная admin_audit_purge_runs — отклонена: две
-- почти идентичные таблицы раздувают schema и усложняют status
-- endpoint (два JOIN'а вместо одного WHERE).
ALTER TABLE audit_purge_runs
    ADD COLUMN IF NOT EXISTS target VARCHAR(64) NOT NULL DEFAULT 'audit_logs';

CREATE INDEX IF NOT EXISTS idx_audit_purge_runs_target_started_at
    ON audit_purge_runs(target, started_at DESC);

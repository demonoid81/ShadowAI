-- PR-A: retention/purge tracking для audit_logs.
--
-- Хранит историю purge-операций. Status endpoint и admin-tooling
-- строят "last_purged_at" и "rows_purged_total" без отдельной БД-
-- aggregation-таблицы. Сам audit_logs остаётся без изменений.
--
-- Каждый запуск `cmd/audit-purge` или embedded scheduler добавляет
-- одну строку. cutoff = таймстамп, старше которого rows были удалены.
CREATE TABLE IF NOT EXISTS audit_purge_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    cutoff TIMESTAMPTZ NOT NULL,
    rows_deleted INT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_audit_purge_runs_started_at
    ON audit_purge_runs(started_at DESC);

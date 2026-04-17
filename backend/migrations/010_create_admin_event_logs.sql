-- PR-D: Admin access audit.
--
-- Отдельная таблица от audit_logs, потому что:
--   - audit_logs содержит end-user LLM-traffic (высокий volume, быстрая
--     retention) — admin actions имеют разные retention/privacy SLA.
--   - смешение ломает dashboard-аналитику (admin reads не должны влиять
--     на cost/tokens/policy_action статистику).
--   - admin events редкие, latency на insert некритична — можно писать
--     синхронно без async worker'а, в отличие от audit_logs.
--
-- Что логируется (PR-D первая волна):
--   - read: GET /audit/logs, /audit/status, /dashboard/*
--   - erase: POST /users/{id}/erase (с counter'ами в metadata)
--   - purge: audit-purge CLI/scheduler (actor NULL, mode=cli|scheduler)
--   - internal-db admin: CRUD sources (мигрируется с audit_logs)
CREATE TABLE IF NOT EXISTS admin_event_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- actor_user_id — admin/service account, инициировавший действие.
    -- NULL для системных операций (scheduler, CLI без JWT).
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    -- action — глагол действия: "read" | "erase" | "purge" | "create"
    -- | "update" | "delete" | ...
    action VARCHAR(64) NOT NULL,
    -- resource — категория объекта: "audit_logs" | "audit_status"
    -- | "dashboard" | "user" | "internal_db_source" | ...
    resource VARCHAR(64) NOT NULL,
    -- target_id — опциональный идентификатор конкретного ресурса
    -- (user_id для erase, source id для internal-db CRUD). NULL для
    -- read list-endpoints.
    target_id VARCHAR(255),
    path VARCHAR(255) NOT NULL,
    method VARCHAR(16) NOT NULL,
    status_code INT NOT NULL,
    success BOOLEAN NOT NULL,
    -- metadata_json — фильтры, counters, mode=cli|scheduler и т.п.
    -- НЕ содержит raw bodies, SQL-query, secrets, DSN (см. privacy notes).
    metadata_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_admin_event_logs_created_at
    ON admin_event_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_event_logs_actor_created
    ON admin_event_logs(actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_event_logs_resource_action
    ON admin_event_logs(resource, action, created_at DESC);

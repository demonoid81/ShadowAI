-- PR-4: inspector modes = disabled/shadow/enforce.
--
-- Добавляем отдельное поле shadow_decisions_json для наблюдений shadow-
-- инспекторов. policy_action НЕ перегружаем: там остаётся фактический
-- enforcement-итог запроса (allowed/blocked/sanitized/warned).
--
-- Формат: JSONB-массив из объектов вида:
--   [{"inspector": "pii", "action": "block", "reason": "...", "severity": "high"}]
-- Пусто/NULL означает "ни один shadow-инспектор не сработал на этом запросе".
--
-- Причина JSONB (а не TEXT): позволяет строить ops-dashboards вида
--   SELECT inspector, count(*) FROM audit_logs,
--          jsonb_array_elements(shadow_decisions_json) AS e
--   GROUP BY inspector;
-- без регулярок и парсинга.
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS shadow_decisions_json JSONB NULL;

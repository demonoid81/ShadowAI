-- PR-F7.3: structured streaming audit outcomes.
--
-- Разделяет смешанную семантику, которая раньше умещалась в
-- policy_action, на три независимых поля:
--
--   policy_action   — policy/security verdict (allowed/blocked/flagged/
--                     sanitized). Не перегружается transport или
--                     accounting смыслом.
--   outcome         — transport-level итог streaming-запроса.
--                     Словарь F7.3: stream_completed, stream_flagged,
--                     stream_blocked, stream_blocked_midflight,
--                     stream_buffered_fallback, stream_transport_error,
--                     stream_usage_parse_failed, stream_budget_exceeded_soft.
--                     Пустая строка = non-streaming (chatReq.Stream=false)
--                     или request-side early reject.
--   fallback_reason — почему incremental не был применён. Non-empty
--                     только когда outcome=stream_buffered_fallback.
--                     Значения: judge_inspector, unsupported_provider,
--                     unsupported_inspector (reserved).
--   usage_source    — откуда взялась accounting truth.
--                     F7.3: final, none. Partial — reserved для F7.4.
--
-- NOT NULL DEFAULT '' — безопасно на существующих rows (пустые
-- строки для legacy записей, что сохраняет backward compat).
--
-- Удаляет compound marker hack из PR-F7.2.1 (streaming_buffered_fallback:
-- <original> в policy_action). После миграции + deploy handler-кода
-- dashboards должны читать outcome/fallback_reason/usage_source как
-- отдельные поля.

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS outcome         VARCHAR(48) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS fallback_reason VARCHAR(48) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS usage_source    VARCHAR(16) NOT NULL DEFAULT '';

# O3.1.2 — SIEM + Streaming Smoke Plan

**Дата:** 2026-04-25  
**Статус:** Подтверждён, ожидает реализации

## Тема
Расширение O3 smoke harness: async SIEM delivery + streaming proxy behavior.

## Контекст
Текущий smoke (migrations, auth/MFA, break-glass, governance, health, SCIM, WORM) зелёный.
Следующий пробел — runtime path: SIEM async queue + streaming proxy wiring.

## Принятые решения

### Структура
- Новый файл: `backend/smoke/siem_streaming_smoke_test.go`
- Build tag: `enterprise && smoke`
- Альтернатива "только unit-тесты" отклонена: цель O3 — интеграционные разрывы

### SIEM smoke (п.1–2)
- Без real PG: FanoutAdminRecorder + HTTPRecorder + fake httptest.Server
- queue=10, batch=3, короткий flush interval
- Проверяем: batch delivery, retry (500→200), non-blocking caller
- Backpressure: queue=2, slow sink, проверка метрики dropped_total

### Streaming smoke (п.3–5)
- Real PG (через startInfra) для audit write path
- proxy.Handler с минимальным wiring: реальный audit.Repository, остальное nil
- Fake OpenAI SSE fixture: локальная копия в smoke package
- Buffered: stream_completed в audit_logs
- Incremental: bytes identity, usage_source
- Fallback: stream_buffered_fallback + fallback_reason (judge_inspector или unsupported_provider)

### CI
- smoke-enterprise job подхватит автоматически
- Таймаут 15m: оставить до измерения

## Открытые вопросы (закрытые)
1. usage_source проверяется опционально через t.Logf — не assertion
2. SSE fixture: локальная копия в smoke, без зависимости от internal test

## Порядок реализации
1. SIEM async + backpressure
2. Streaming buffered
3. Streaming incremental
4. Streaming fallback
5. CI comment update

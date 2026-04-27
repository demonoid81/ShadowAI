# bd ShadowAI-215 — PR-L7 legal hold SLA / DPO signals

## Контекст

После L6 legal hold поддерживает `whole_user` и `date_range` enforcement. Локальные документы фиксировали остаточный compliance gap: нет автоматического SLA escalation для `pending`/`release_pending` holds и нет DPO/legal signal при DSAR, заблокированном legal hold.

CASS перед реализацией был проверен, но недоступен как актуальный источник: `cass health` вернул `index stale`. Поэтому источником истины стали локальные docs и фактический код.

## Цель

Добавить автоматические machine-readable сигналы для legal/compliance operations без внедрения отдельного email/SMS/webhook transport.

## Входит в объём

- Config/env для SLA thresholds и scan interval.
- Periodic scheduler в enterprise runtime.
- SLA scan для `pending` и `release_pending`.
- Dedupe per hold/status/day bucket через `admin_event_logs`.
- Admin events + SIEM fanout через существующий recorder.
- Prometheus metrics и Helm alerts.
- DPO/legal signal при DSAR blocked-by-hold.

## Не входит в объём

- Email/SMS/PagerDuty/webhook transport.
- `query_scope` selector language.
- Изменение legal hold lifecycle states.
- UI.

## План реализации

1. Добавить red tests для SLA scan, dedupe, release_pending age и DSAR blocked signal.
2. Реализовать `SLAConfig`, `SLAReport`, `EmitSLASignals`.
3. Добавить PG repository методы для SLA candidates и dedupe lookup.
4. Добавить config fields, prod validation и runtime scheduler wiring.
5. Добавить Prometheus metrics и Helm alerts.
6. Обновить docs/history.
7. Прогнать targeted/full checks, закрыть bd и сделать commit.

## Размышления

Рассмотрены варианты:

- Отправлять email/webhook прямо из приложения.
- Делать только pull-based endpoint без событий.
- Использовать существующий admin_event/SIEM/Prometheus канал как v1.

Принято решение использовать existing evidence/observability path: `admin_event_logs` как durable trail, SIEM fanout как внешний signal, Prometheus alerts как operator trigger.

Альтернатива с email/webhook отклонена для v1: она требует credential lifecycle, retry semantics и customer-specific routing, а в проекте уже есть SIEM и Prometheus pipeline.

Для dedupe принято решение использовать day bucket в metadata и lookup в `admin_event_logs`. Это сохраняет append-only audit trail и не требует новой mutable state table.

## Критерии готовности

- `LEGAL_HOLD_PENDING_SLA_HOURS`, `LEGAL_HOLD_RELEASE_PENDING_SLA_HOURS`, `LEGAL_HOLD_SLA_SCAN_INTERVAL`, `DSAR_DPO_SIGNAL_ENABLED` добавлены в config.
- Scheduler запускает SLA scan при positive interval.
- Pending и release_pending thresholds независимы.
- Повторный scan в том же day bucket не создаёт duplicate event.
- DSAR blocked-by-hold создаёт отдельный DPO/legal signal.
- Метрики не содержат PII labels.
- Helm alerts рендерятся.

## Проверка

- `go test -tags enterprise ./internal/legalhold -run 'TestEmitSLASignals' -count=1`
- `go test -tags enterprise ./internal/auth -run 'TestEraseUser_HoldActive_EmitsDPOSignalWhenEnabled|TestEraseUser_HoldActive_Returns409' -count=1`
- `go test -tags enterprise ./internal/config -run 'TestValidateStartupConfig_LegalHoldSLA_InvalidValues|TestValidateStartupConfig_LegalHoldSecretOK' -count=1`
- `go test -tags enterprise ./internal/legalhold ./internal/auth ./internal/adminaudit ./internal/config ./internal/metrics -count=1`
- `go test -tags enterprise ./... -count=1`
- `go test ./... -count=1`
- `make helm-validate`
- `git diff --check`

## Риски / зависимости

- Multi-replica deployments can emit one event per replica before the first write is visible. Persistent admin-event dedupe narrows this, but no distributed lock is introduced in L7.
- DPO/legal signal is a durable event, not an external notification transport.
- `query_scope` remains unsupported.

## Roadmap

### v1

- Admin event + SIEM + Prometheus signals.
- Day-bucket dedupe.

### v2+

- Webhook/email/PagerDuty transport.
- Dedicated SLA state table if daily bucket is insufficient.
- `query_scope` legal hold selector language.

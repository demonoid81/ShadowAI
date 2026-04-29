# ShadowAI-vef / OPS2 — Backend-backed production signals API

## Контекст

После UX10 Operations page разделяет direct live endpoints и static runbooks. Но production-level сигналы по evidence export, retention audit report, Prometheus alerts и last-success состояниям оставались `unknown`, потому что frontend не должен ходить в Prometheus/Kubernetes напрямую и backend не имел безопасного агрегирующего endpoint.

## Цель

Добавить admin-only `/api/operations/status`, который возвращает безопасный read-only snapshot production signals для Operations UI. Endpoint не раскрывает секреты и не утверждает success, если источник данных не интегрирован.

## План реализации

1. Создать `backend/internal/operations` с machine-readable status model.
2. Покрыть `BuildSnapshot` тестами для `ok`, `warn`, `error`, `unknown`.
3. Добавить handler `GET /api/operations/status` под существующий admin router.
4. Подключить Operations UI к endpoint как backend-backed production summary.
5. Добавить ru/en i18n для backend signal labels.
6. Выполнить backend/frontend проверки.

## Размышления

Рассмотрены два варианта: сразу интегрировать Prometheus/Kubernetes API или начать с безопасного status snapshot. Принято решение делать snapshot v1: он закрывает API contract для UI и не требует operator credentials в приложении.

Альтернатива “рисовать CronJob success по Helm config” отклонена: наличие CronJob template или env-флага не доказывает последний успешный запуск. Поэтому `evidence_export_cronjob`, `evidence_audit_report_cronjob` и `prometheus_alerts` остаются `unknown` до появления реального source integration.

Принято решение не возвращать секреты, raw endpoints и credentials. Для sensitive controls API возвращает только boolean/configured markers: `chain_enabled`, `signing_enabled`, `pubkey_id_configured`, `SIEMEnabled`, `BYOKEnabled`.

## Scope In

- Backend status model and handler.
- Route under existing admin/global_admin middleware.
- Runtime dependency readiness from DB/Redis ping.
- Config-based audit retention / anchors / SIEM posture.
- Unknown placeholders for external scheduler and Prometheus state.
- Operations UI production status cards.

## Scope Out

- Browser-to-Prometheus integration.
- Kubernetes client.
- Last successful CronJob timestamps.
- Alertmanager state aggregation.
- Secret display.

## Definition of Done

- `GET /api/operations/status` is protected by existing admin router.
- Response contains safe production signal summary.
- Missing source is `unknown`, not `ok`.
- Operations UI consumes endpoint and renders summary/signals.
- Unit tests cover ok/degraded/unknown.
- Frontend build and targeted backend tests pass.

## Roadmap

v1: safe operations status API + UI consumption.

v2+: Prometheus/kube-state-metrics integration, last-success timestamps from CronJob events, Alertmanager state aggregation, explicit retry controls.

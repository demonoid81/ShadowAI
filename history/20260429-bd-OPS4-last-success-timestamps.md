# ShadowAI-76a / OPS4 — Operations last-success timestamps

## Контекст

OPS3 добавил Prometheus-backed production signals для
`/api/operations/status`: backend может выполнять PromQL и превращать numeric
violation count в `ok/warn/error/unknown`.

Оставшийся gap: `0 failed jobs` не доказывает, что evidence export или evidence
audit report недавно успешно выполнялись. Operations UI должен показывать
последний успешный запуск и stale-состояние.

## Цель

Добавить last-success telemetry для `evidence_export_cronjob` и
`evidence_audit_report_cronjob`: `last_success_at`, `age_seconds`,
`stale_after_seconds`.

## План реализации

1. Добавить red-тесты для config load и Prometheus timestamp enrichment.
2. Расширить `config.Config` и `RuntimeConfig`.
3. Реализовать backend staleness logic в `internal/operations`.
4. Обновить Operations UI details rendering.
5. Добавить Helm values comments.
6. Выполнить backend/frontend/Helm проверки.

## Размышления

Рассмотрены варианты: Prometheus timestamp query, Kubernetes Job API и запись
last-success в ShadowAI DB. Принято решение использовать Prometheus timestamp
query: это продолжает OPS3, не требует browser-to-Prometheus и не расширяет
Kubernetes RBAC приложения.

Kubernetes client отклонён для OPS4: он требует отдельной RBAC/security модели
и увеличивает blast radius backend-а.

DB-backed last-success отклонён для OPS4: evidence export/audit report
CronJobs запускаются отдельными CLI/container flows, и запись их результата в
app DB требует отдельного producer contract.

## Scope In

- `OPERATIONS_EVIDENCE_EXPORT_LAST_SUCCESS_QUERY`
- `OPERATIONS_EVIDENCE_AUDIT_REPORT_LAST_SUCCESS_QUERY`
- `OPERATIONS_EVIDENCE_EXPORT_STALE_AFTER`
- `OPERATIONS_EVIDENCE_AUDIT_REPORT_STALE_AFTER`
- Unix timestamp seconds contract.
- Backend staleness evaluation.
- UI rendering for timestamp/age/stale threshold.

## Scope Out

- Kubernetes API.
- Alertmanager API.
- UI retry controls.
- ShadowAI DB run-history table.
- Prometheus auth/token support.

## Definition of Done

- Без новых env OPS3 behavior сохраняется.
- Fresh timestamp не ухудшает `ok`.
- Stale timestamp делает CronJob signal `warn` при count-query `0`.
- Failed count-query/violation остаётся `error`.
- Empty timestamp query не превращается в success.
- JSON response не содержит raw PromQL/URL/secrets.
- Backend/frontend/Helm checks проходят.

## Roadmap

v1: last-success telemetry через Prometheus timestamp query.

v2+: Kubernetes events, Alertmanager aggregation, retry controls.

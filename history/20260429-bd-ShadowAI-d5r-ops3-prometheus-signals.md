# ShadowAI-d5r / OPS3 — Prometheus-backed operations signals

## Контекст

OPS2 добавил backend endpoint `/api/operations/status` и подключил его к
Operations UI. Endpoint честно возвращает `unknown` для сигналов, где backend
не имеет источника истины: evidence export CronJob, evidence audit report
CronJob и Prometheus alerts.

## Цель

Добавить безопасную backend-интеграцию Prometheus HTTP API для production
signals. Frontend не должен ходить в Prometheus напрямую, а backend не должен
раскрывать URL, credentials или raw secret-bearing config.

## План реализации

1. Расширить `config.Config` полями `OPERATIONS_PROMETHEUS_*`.
2. Добавить Prometheus query client в `backend/internal/operations`.
3. Покрыть parsing/status mapping unit-тестами через `httptest`.
4. Подключить Prometheus enrichment в `Handler.Status`.
5. Добавить Helm values comments для operator configuration.
6. Выполнить backend проверки, `ast-index update`, `git diff --check`.

## Размышления

Рассмотрены варианты Kubernetes client, Alertmanager API и Prometheus HTTP API.
Принято решение начать с Prometheus HTTP API: kube-state-metrics и alert rules
уже являются стандартным observability surface, а backend получает только
числовой результат PromQL expression.

Альтернатива с hardcoded PromQL отклонена. Разные clusters используют разные
CronJob names, namespaces и labels, поэтому expressions должны быть
configurable через env/Helm.

Альтернатива возвращать raw query/Prometheus URL в details отклонена. Для UI
достаточно `query_configured`, `value` и статуса; URL и query могут раскрывать
внутреннюю observability topology.

## Scope In

- `OPERATIONS_PROMETHEUS_URL`
- `OPERATIONS_PROMETHEUS_TIMEOUT`
- `OPERATIONS_EVIDENCE_EXPORT_QUERY`
- `OPERATIONS_EVIDENCE_AUDIT_REPORT_QUERY`
- `OPERATIONS_PROMETHEUS_ALERTS_QUERY`
- HTTP client на стандартной библиотеке.
- Status mapping: `0 = ok`, `>0 = error` для CronJob signals,
  `>0 = warn` для alerts.

## Scope Out

- Kubernetes client.
- Alertmanager API.
- Browser-to-Prometheus.
- Retry controls.
- Secret display.

## Definition of Done

- Без `OPERATIONS_PROMETHEUS_URL` поведение OPS2 сохраняется.
- При настроенном Prometheus URL и query три external signals становятся
  backend-backed.
- Ошибка Prometheus не ломает endpoint и не возвращает HTTP 500.
- Empty result отображается как `unknown`.
- Тесты покрывают success, error, empty result и config load.

## Roadmap

v1: Prometheus-backed status queries with configurable expressions.

v2+: Alertmanager aggregation, Kubernetes event details, explicit retry controls.

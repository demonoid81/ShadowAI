# ShadowAI-d5r — примеры

## Happy path 1: evidence export healthy

Вход: `OPERATIONS_PROMETHEUS_URL` настроен, `OPERATIONS_EVIDENCE_EXPORT_QUERY`
возвращает `0`.

Ожидание: signal `evidence_export_cronjob` получает `status=ok`,
`source=prometheus`, `details.value=0`.

## Happy path 2: active alerts visible

Вход: `OPERATIONS_PROMETHEUS_ALERTS_QUERY` возвращает `2`.

Ожидание: signal `prometheus_alerts` получает `status=warn`, потому что
Prometheus доступен, но есть активные alert violations.

## Edge case 1: Prometheus не настроен

Вход: `OPERATIONS_PROMETHEUS_URL=""`.

Ожидание: OPS2 поведение сохраняется; external signals остаются `unknown`, а
endpoint `/api/operations/status` продолжает отвечать HTTP 200.

## Edge case 2: empty vector

Вход: Prometheus возвращает `success` с пустым `result`.

Ожидание: signal становится `unknown`, потому что backend не получил
доказательство ни health, ни violation.

## Failure case: Prometheus query error

Вход: Prometheus возвращает HTTP 500 или `status="error"`.

Ожидание: соответствующий signal получает `status=error`; весь snapshot всё
равно возвращается HTTP 200, чтобы Operations UI мог показать деградацию.

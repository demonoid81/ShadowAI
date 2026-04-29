# ShadowAI-76a / OPS4 — примеры

## Happy path 1: свежий evidence export

Вход: count-query возвращает `0`, last-success query возвращает Unix timestamp
на 2 часа раньше текущего времени, stale threshold — 26 часов.

Ожидание: `evidence_export_cronjob.status=ok`, details содержат
`last_success_at`, `age_seconds=7200`, `stale_after_seconds=93600`.

## Happy path 2: свежий audit report

Вход: `OPERATIONS_EVIDENCE_AUDIT_REPORT_LAST_SUCCESS_QUERY` настроен и
возвращает свежий timestamp.

Ожидание: Operations UI показывает дату последнего успешного запуска и возраст
без raw PromQL.

## Edge case 1: timestamp query не настроен

Вход: OPS3 count-query настроен, last-success query пустой.

Ожидание: существующий status сохраняется, details содержит
`last_success_configured=false`; fake success не рисуется.

## Edge case 2: stale timestamp

Вход: count-query возвращает `0`, но last-success старше threshold.

Ожидание: итоговый status становится `warn`, потому что отсутствие failed jobs
не доказывает свежий successful run.

## Failure case: count-query violation

Вход: count-query возвращает `1`, last-success свежий.

Ожидание: итоговый status остаётся `error`; fresh timestamp не маскирует
активную проблему.

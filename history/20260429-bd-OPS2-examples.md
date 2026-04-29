# ShadowAI-vef / OPS2 — Examples

## Happy path 1 — Runtime dependencies OK

Вход: DB ping OK, Redis ping OK.

Ожидаемый результат: signal `readiness` имеет status `ok`, details содержат `db=ok` и `redis=ok`.

## Happy path 2 — Evidence anchors configured

Вход: `AUDIT_ANCHOR_INTERVAL > 0`, `AUDIT_ANCHOR_SINK=file://`, signing key configured, chain enabled.

Ожидаемый результат: signal `evidence_anchors` имеет status `ok`; API возвращает только markers, без signing private key и chain secret.

## Edge case 1 — Runtime dependency degraded

Вход: DB ping OK, Redis ping failed.

Ожидаемый результат: signal `readiness` имеет status `error`, details содержит `failed_checks=["redis"]`.

## Edge case 2 — Anchors scheduled without external sink

Вход: `AUDIT_ANCHOR_INTERVAL > 0`, но `AUDIT_ANCHOR_SINK=""`.

Ожидаемый результат: signal `evidence_anchors` имеет status `warn`, потому что PG anchor без external witness не равен WORM-grade external evidence.

## Failure case — Production status endpoint unavailable in UI

Вход: frontend `GET /api/operations/status` получает network/403/404.

Ожидаемый результат: Operations UI показывает production summary как `unknown`, не как successful check.

## Unknown source case — CronJob last success not integrated

Вход: Helm может содержать CronJob, но backend не имеет Kubernetes/Prometheus source.

Ожидаемый результат: `evidence_export_cronjob`, `evidence_audit_report_cronjob` и `prometheus_alerts` имеют status `unknown`.

## Safety case — No secret exposure

Вход: config содержит `AUDIT_CHAIN_SECRET`, `AUDIT_ANCHOR_SIGNING_KEY`, SIEM bearer token или BYOK token.

Ожидаемый результат: `/api/operations/status` не возвращает raw secret values; tests проверяют отсутствие secret markers в serialized snapshot.

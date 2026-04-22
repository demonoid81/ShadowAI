# bd-ShadowAI-p5k: PR-A — Audit Privacy Hardening

**Дата:** 2026-04-17
**Статус:** реализовано.

## Контекст

До PR-A audit trail хранился verbatim (request_body + response_body +
shadow_decisions_json), без retention/purge flow. Для enterprise/prod
этот контур был blocker: data minimization отсутствовала, GDPR/SOC2
audit rows накапливались бесконечно.

Ревью поставил P0: без этой работы semantic_v2 rollout в prod
невозможен — сам по себе rollout увеличит объём аудируемых данных.

## Контракт (финальный)

### Payload mode

| mode       | request_body                              | response_body                             |
|------------|-------------------------------------------|-------------------------------------------|
| `none`     | NULL                                      | NULL                                      |
| `metadata` | `{"stored":"metadata","bytes":N,"messages":M}` | `{"stored":"metadata","bytes":N}`   |
| `redacted` | DLP.Sanitize(raw) → truncated             | DLP.Sanitize(raw) → truncated             |
| `full`     | raw → truncated                           | raw → truncated                           |

- **Default = `redacted`** (secure-by-default; breaking vs prior behaviour,
  но до GA это приемлемый trade-off).
- **`redacted` + `dlpSvc=nil` → fallback `metadata`** (не `full`: "не уверены — меньше данных").
- **`full` выводит startup-warning** в logs.
- **Invalid `AUDIT_PAYLOAD_MODE` → fallback `redacted`** (warning в logs).
- Truncation до 4000 chars с маркером `...truncated`.

### Retention + purge

- `AUDIT_RETENTION_DAYS=N` (default 0 = no-purge).
- `AUDIT_PURGE_INTERVAL=duration` (default 0 = scheduler off; CLI остаётся
  основным путём).
- `AUDIT_PURGE_CHUNK_SIZE=1000` (default) — защита от lock'ов.
- Purge = **hard DELETE** (не anonymize), чанками по `chunk_size`.
- Shadow decisions живут по **тому же TTL** (single retention, MVP).
- **`audit_purge_runs`** — служебная таблица (migration 008):
  `(id, started_at, completed_at, cutoff, rows_deleted)` — источник
  истории для status endpoint.

### Status endpoint

`GET /audit/status` (admin-only):
```json
{
  "payload_mode": "redacted",
  "retention_days": 30,
  "last_purged_at": "2026-04-17T12:00:00Z",
  "rows_purged_total": 12345,
  "scheduler_enabled": true
}
```
Не светит secrets (DATABASE_URL, API keys).

## Реализация

### `internal/audit/payload_mode.go`
- `PayloadMode` enum + `ParsePayloadMode` (case-insensitive + trim).
- `TransformBodies(mode, req, resp, dlpSvc, findings)` → `(reqOut, respOut)`.
- `metadataSummary` с best-effort messages count из OpenAI-style JSON.
- `truncate` с видимым ASCII marker.
- 9 тестов: все модальности, JSON/non-JSON metadata, DLP fallback,
  truncation.

### `internal/audit/retention.go`
- `Repository.PurgeOlderThan(ctx, cutoff, chunkSize)` — chunked DELETE
  через `DELETE FROM audit_logs WHERE id IN (SELECT id ... LIMIT N)`
  (PG не поддерживает LIMIT в DELETE напрямую).
- `RecordPurgeRun / LastPurgeRun / TotalRowsPurged` — операторы над
  `audit_purge_runs`.

### Repo interface (`internal/audit/service.go`)
Расширен 4 методами (+ stubs в `captureAuditRepo` / `recordingRepo` в
тестовых файлах). Эти методы требуются CLI и scheduler'ом.

### `internal/proxy/audit_shadow.go::auditLog`
Единая точка применения PayloadMode. Handler каждый раз передаёт
raw/sanitized bodies в `log.RequestBody/ResponseBody`, `auditLog`
вызывает `TransformBodies` с `h.auditPayloadMode` + `h.dlpSvc`.

Тесты без явного mode получают fallback `PayloadModeFull` (backward
compat). Production `main.go` всегда передаёт явное значение.

### `cmd/audit-purge`
CLI с `--retention-days / --dry-run / --chunk-size / --database-url`.
Exit 0 pass, 1 runtime. 4 unit-теста (flag validation) + integration
через live Postgres (вручную оператором).

### Scheduler в `cmd/shadowai/main.go`
Goroutine стартует при `AUDIT_PURGE_INTERVAL>0 && AUDIT_RETENTION_DAYS>0`.
Периодически зовёт `PurgeOlderThan` + `RecordPurgeRun`. Отменяется
через `connectivityCtx` (общий shutdown-signal с provider connectivity).

### Config (`internal/config/config.go`)
+4 env vars: `AUDIT_PAYLOAD_MODE` (default `redacted`),
`AUDIT_RETENTION_DAYS` (0), `AUDIT_PURGE_INTERVAL` (0),
`AUDIT_PURGE_CHUNK_SIZE` (1000).

### Routing (`cmd/shadowai/main.go`)
`admin.HandleFunc("/audit/status", auditHandler.Status).Methods("GET")`.

## Тесты

Всего добавлено **15 unit-тестов**, все проходят:
- 2 × `ParsePayloadMode` (valid/invalid).
- 5 × `TransformBodies` (none/metadata happy/metadata non-JSON/redacted/fallback).
- 2 × `TransformBodies_Full` (keep/truncate).
- 4 × `cmd/audit-purge` (missing retention/zero/negative chunk/missing DB URL).
- 2 × `audit_handler.Status` (exposes config / no PII leak).

`go test ./...` зелёный, включая полный regression proxy/firewall/firewallbench.

## Размышления

- **Backward compat vs secure-by-default.** Default `redacted` — breaking
  для существующих deploy (те, кто полагался на raw bodies в прод
  будут получать DLP-sanitized). До GA это приемлемо; в CHANGELOG и
  docs указать явно.
- **Retention = hard DELETE, не anonymize.** Проще, меньше mental
  overhead. Если потом понадобится long-term analytics — отдельная
  aggregate-таблица в PR-A.1. Для MVP dashboard "сужается" с retention,
  что нормально.
- **`audit_purge_runs` вместо embedded state.** Сервер перезагружается;
  хотим `rows_purged_total` переживать restart без отдельного KV.
  БД-row solves это, плюс даёт audit-trail самих purge операций
  (полезно при compliance review).
- **Single retention для bodies + shadow_decisions.** Упрощает operator
  model. Если tuning потребует долгоживущих shadow, в v2 появится
  `AUDIT_SHADOW_RETENTION_DAYS`.
- **Fallback `redacted → metadata` при отсутствии DLP.** "Не уверены =
  меньше данных" — это противоположно `full` по смыслу. Оператор видит
  в audit, что body не содержит raw (и в logs — если DLP не запущен,
  warning на startup).

## Definition of Done

- [x] 4 PayloadMode с точной семантикой + fail-safe fallback.
- [x] Default `redacted`, startup warning для `full`.
- [x] `AUDIT_RETENTION_DAYS` + hard DELETE.
- [x] `AUDIT_PURGE_INTERVAL` optional scheduler.
- [x] `cmd/audit-purge` CLI (с `--dry-run`).
- [x] `audit_purge_runs` таблица + репо методы.
- [x] `GET /audit/status` endpoint (без secrets).
- [x] 15 unit-тестов; `go test ./...` зелёный.
- [x] main.go wire с валидацией mode, startup warning, scheduler.

## Что OUT of scope (отдельные PR)

- **Backfill существующих rows** — migration-heavy, отдельный PR.
- **DSAR / tenant-purge** — требует `tenant_id` в audit_logs.
- **RBAC + access-audit** (кто читал audit rows) — отдельный layer.
- **Secrets rotation** — env baseline OK, отдельная тема для infra.
- **`AUDIT_SHADOW_RETENTION_DAYS`** — если появится нужда.
- **`audit_daily_aggregates`** — long-term analytics, когда понадобится.

## Operational notes

**Breaking change disclosure:** existing deploy получает `redacted` по
умолчанию. Операторы, которым нужен raw для debugging, должны явно
установить `AUDIT_PAYLOAD_MODE=full` (и увидят warning в logs).

**Prod CI integration:**
```bash
# backend/cmd/audit-purge — на cron (ежедневно/еженедельно):
./audit-purge --retention-days 30 --chunk-size 1000
```

Alternative: embedded scheduler через env:
```
AUDIT_PURGE_INTERVAL=24h
AUDIT_RETENTION_DAYS=30
```

## Что дальше

Согласно rollout-плану (см. предыдущие history):
1. Merge `pr-a-audit-privacy` в master.
2. Прод-деплой с `AUDIT_PAYLOAD_MODE=redacted` + `AUDIT_RETENTION_DAYS=30`.
3. Мониторить `audit_purge_runs` через `/audit/status`.
4. Дальше — semantic_v2 shadow rollout (как планировалось).

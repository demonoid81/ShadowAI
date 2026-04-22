# PR-S1: Admin Event SIEM Mirror (HTTP fail-open)

## Контекст
После закрытия admin user-governance trail (PR-G0/G0.1/G0.2/B),
следующий compliance ask для regulated enterprise — tamper-resistant
external evidence stream. PR-S1 закрывает это через HTTP mirror.

Это **security/compliance control**, не analytics/observability
integration. Payload — строго те же поля, что уже в
`admin_event_logs`; никаких raw-body/token/SQL dump'ов.

## Scope (In)
- Новый пакет `backend/internal/siem/` (`//go:build enterprise`):
  - `types.go` — `Event`, `Recorder`, `FromAdminEvent` converter, `NoopRecorder`.
  - `http_recorder.go` — HTTP POST JSON envelope; bearer-auth
    optional; fail-open (ошибки → metrics + log).
  - `fanout.go` — `FanoutAdminRecorder` satisfies
    `adminaudit.Recorder`, дублирует event на DB + SIEM.
  - `metrics.go` — 4 Prometheus метрики с label `sink="http"`.
- Конфиг (core, `internal/config/config.go`): `SIEM_ENABLED`,
  `SIEM_ENDPOINT`, `SIEM_TIMEOUT` (default 3s), `SIEM_BEARER_TOKEN`,
  `SIEM_INSECURE_SKIP_VERIFY`.
- Wiring в `cmd/shadowai/enterprise_wire.go`: если
  `SIEM_ENABLED=true` и endpoint задан, оборачиваем
  `adminAuditSvc` → `FanoutAdminRecorder{DB, SIEM}`. Handlers
  продолжают работать с `adminaudit.Recorder` interface без
  изменений.
- Scheduler events (PR-A / PR-D.1 purge) тоже идут через fanout —
  `purge` actions видны в SIEM.
- 14 TDD тестов под `//go:build enterprise`:
  - 8 для `HTTPRecorder` (payload, auth, empty endpoint, 500, timeout,
    payload-no-extra-fields, nil-receiver, sinkHost).
  - 6 для `FanoutAdminRecorder` (both called, nil-SIEM, nil-DB,
    both-nil, nil-receiver, ordering DB-first, FromAdminEvent
    preserving fields).

## Scope (Out, v1.1+)
- Syslog sink.
- OTel logs exporter.
- Batching / queueing worker.
- Retry с exponential backoff.
- Per-tenant stream partitioning.
- Exactly-once delivery guarantees.
- Audit-logs / proxy-traffic mirror (только admin_event_logs в v1).

## Reliability policy
- **Fail-open**. SIEM unavailability не ломает primary endpoint.
- HTTP non-2xx → metric `shadowai_siem_fail_total` + warning log
  (с host-only, без token).
- Timeout (context deadline / net) → `shadowai_siem_timeout_total`.
- Invalid URL / marshal failure → `shadowai_siem_fail_total`.
- DB write (primary) выполняется ПЕРЕД SIEM push — fanout гарантирует
  порядок (test `TestFanout_DBFirst_SIEMAfter`).

## Privacy contract
Payload — envelope `{source, stream, event}`; event содержит
ровно поля из `adminaudit.Event` + `created_at`. Regression
guard: `TestHTTPRecorder_PayloadNoExtraFields` проверяет
top-level keys.

Запрещено (проверка через regression tests и документация):
- raw email
- request/response bodies
- SQL text
- bearer tokens / API keys
- DSN / provider secrets
- request headers

Payload идентичен тому, что уже в `admin_event_logs`. Если admin
event в PG не содержит PII, SIEM mirror тоже не содержит.

## Metrics (Prometheus)
```
shadowai_siem_requests_total{sink="http"}  # counter, total attempts
shadowai_siem_fail_total{sink="http"}      # counter, non-2xx / net err
shadowai_siem_timeout_total{sink="http"}   # counter, deadline/net timeout
shadowai_siem_latency_seconds{sink="http"} # histogram, end-to-end RTT
```

Label cardinality минимальна (только `sink`) — никаких endpoint/
action/actor labels, чтобы не взрывать series и не leak'ать
identifiers через Prometheus.

## Acceptance criteria (всё выполнено)
- [x] `SIEM_ENABLED=false` → поведение идентичное старому (DB-only).
- [x] `SIEM_ENABLED=true` + endpoint задан → каждый admin event
      дублируется в HTTP sink.
- [x] Недоступный sink не ломает primary request path (200s на
      admin endpoints продолжают возвращаться).
- [x] Fail/timeout видны в Prometheus metrics.
- [x] В SIEM payload нет новых PII-полей по сравнению с
      `admin_event_logs`.
- [x] `go build ./...` + `go build -tags enterprise ./...` оба
      компилируются.
- [x] `go test ./...` + `go test -tags enterprise ./...` оба
      полностью зелёные.

## Проверка
```bash
cd backend
go test -tags enterprise ./internal/siem -v -count=1   # 14 тестов PASS
go test ./... -count=1                                   # core matrix green
go test -tags enterprise ./... -count=1                  # enterprise matrix green
```

Ручная (после deploy с enterprise tag + SIEM_ENABLED=true):
```bash
# Настроить mock sink
python3 -m http.server 8088 &
# Или использовать httpbin / Splunk HEC в dev

export SIEM_ENABLED=true
export SIEM_ENDPOINT=http://localhost:8088/ingest
export SIEM_BEARER_TOKEN=test-secret

# Запустить shadowai enterprise build
go build -tags enterprise -o shadowai ./cmd/shadowai
./shadowai &

# Триггернуть admin event
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8080/api/users
# Проверить что mock sink получил payload.

# Проверить metrics:
curl http://localhost:8080/metrics | grep shadowai_siem
```

## Phased rollout
### Phase 1 (v1, этот PR)
Mirror всех admin_event_logs events — они уже fan-in'ятся из:
- GET/PUT /api/users/* (PR-G0/G0.1/G0.2)
- POST /users/{id}/erase (PR-B)
- GET /audit/logs, /audit/status, /dashboard/* (PR-D)
- POST /admin-events purge (PR-D.1)
- governance CRUD (PR-G1)

### Phase 2 (v1.1)
- Syslog sink.
- OTel logs exporter.
- Batching/queueing для high-volume deploys.

### Phase 3 (v2)
- WORM-primary storage: admin events пишутся сначала в external
  append-only, потом реплика в PG для query. Требует redesign
  storage layer.

## Риски / допущения
- **Sync push блокирует request handler до timeout** (default 3s).
  При высокой volume admin events или медленном sink это может
  увеличить latency admin endpoints на up to 3s. В v1 acceptable
  (admin events — редкие, ~10 req/min для нормального operator
  usage). В v1.1 добавим async queue.
- **Нет retry**. Event lost если sink недоступен в момент push.
  Acceptable: PG admin_event_logs остаётся source of truth —
  operator может replay через external tool (`pg_dump` → push).
- **InsecureSkipVerify** доступен для dev/test против
  self-signed SIEM endpoints. Документирован как НЕ для prod
  (`SIEM_INSECURE_SKIP_VERIFY=true` в prod deploy — config warn).

## History
- Plan: этот файл.
- Examples: `20260422-bd-pr-s1-examples.md`.

## Roadmap next
После PR-S1 доступны три трека:
1. **G2**: role-based governance (allowlist per role + SSO role source).
2. **Legal hold**: `pending_erasures` table + approver workflow.
3. **Firewall/runtime track**: semantic_v2 shadow rollout, partial
   enforce, PR-7 streaming.

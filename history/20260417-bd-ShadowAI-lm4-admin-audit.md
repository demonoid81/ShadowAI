# bd-ShadowAI-lm4: PR-D — Admin Access Audit (admin_event_logs)

**Дата:** 2026-04-17
**Статус:** реализовано.

## Контекст

PR-A (payload privacy + retention) и PR-B (DSAR erasure) закрыли
data-minimization и right-to-erasure. Оставался gap: **никто не
знал, кто читал audit/dashboard**. `/audit/logs`, `/audit/status`,
`/dashboard/*` — без admin-access trail; internaldb admin CRUD писал
в `audit_logs` и смешивал control-plane с user LLM-traffic.

PR-D вводит отдельную таблицу `admin_event_logs` и запись admin reads/
actions для compliance (SOC 2 CC7.2, ISO 27001 A.12.4).

## Контракт (финальный)

### Отдельная таблица `admin_event_logs`

Не reuse `audit_logs` потому что:
- разные SLA на retention (admin events должны жить дольше);
- admin reads не должны влиять на cost/tokens aggregations в
  `audit_logs`-dashboards;
- async vs sync writes: user traffic высоковолatильный → async worker;
  admin events редкие → sync запись без drop-risk.

Schema (migration 010):
```
id UUID PK
actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL  (NULL для CLI/scheduler)
action VARCHAR(64)       NOT NULL  -- read|erase|purge|create|update|delete
resource VARCHAR(64)     NOT NULL  -- audit_logs|audit_status|dashboard|user|internal_db_source
target_id VARCHAR(255)            -- optional (erase → user_id; internaldb → source name)
path VARCHAR(255)        NOT NULL
method VARCHAR(16)       NOT NULL
status_code INT          NOT NULL
success BOOLEAN          NOT NULL
metadata_json JSONB                -- filters, counters, mode (masked, без raw bodies)
created_at TIMESTAMPTZ   NOT NULL
```

Индексы: `created_at DESC`, `(actor_user_id, created_at DESC)`,
`(resource, action, created_at DESC)`.

### Что пишется (первая волна PR-D)

| Endpoint / Source              | action | resource              | metadata                                 |
|-------------------------------|--------|------------------------|------------------------------------------|
| GET /audit/logs               | read   | audit_logs             | filters (user_id, model, policy_action, has_shadow, limit, offset, total) |
| GET /audit/status             | read   | audit_status           | —                                         |
| GET /dashboard/stats          | read   | dashboard              | endpoint=stats                           |
| GET /dashboard/usage          | read   | dashboard              | endpoint=usage, points_count             |
| GET /dashboard/top-users      | read   | dashboard              | endpoint=top_users, users_count          |
| POST /users/{id}/erase        | erase  | user                   | status, audit_rows_scrubbed, budgets_deleted |
| cmd/audit-purge CLI           | purge  | audit_logs             | mode=cli, cutoff, rows_deleted [, error] |
| embedded purge scheduler      | purge  | audit_logs             | mode=scheduler, cutoff, rows_deleted [, error] |
| internal-db admin CRUD        | create/update/delete | internal_db_source | source, operation, pii_detected, duration_ms [, error] |

### Privacy guardrails

`metadata_json` **НЕ содержит**:
- raw request/response bodies,
- raw SQL query,
- DSN / connection strings,
- API keys / secrets,
- full user payload.

Только filters, counters, success flags, mode=cli|scheduler. Для
internaldb admin: только `source` name + operation, НЕ rawPayload.

### New API

`GET /api/admin-events?actor_user_id=&resource=&action=&limit=&offset=` —
admin-only list endpoint для расследований.

## Реализация

### `internal/adminaudit/` (новый пакет)

- `repository.go`: `Insert` (sync), `List` (filters + pagination),
  null-safe Scan для optional полей.
- `service.go`: `Service{Record}`, `Event` struct, `Recorder`
  interface. Marshal Metadata в JSON; insert error логируется,
  caller не падает (fail-open для availability).
- `handler.go`: `GET /api/admin-events`.

### Migration 010
`admin_event_logs` + 3 индекса (lookup по времени, по актору,
по resource/action).

### Handler integration

- `audit.Handler` — +`adminaudit.Recorder` в DI; `List/Status`
  вызывают `recordAdminRead` с filters-metadata.
- `dashboard.Handler` — +recorder; 3 endpoint'а пишут event.
- `auth.Handler.EraseUser` — +recorder; `recordErase` с counter'ами.
- `cmd/audit-purge` — создаёт свой `adminaudit.Service` на DB-conn,
  пишет action=purge mode=cli (успех + fail paths).
- Embedded scheduler в `main.go` — action=purge mode=scheduler.
- `internaldb.Handler.auditAdminRequest` — переключён с
  `audit_logs` (writeAudit) на `adminaudit.Recorder`. Больше не
  дублируется. Pii_detected в metadata вместо PIITypes column.

### Wiring в `main.go`

```
adminAuditRepo := adminaudit.NewRepository(db)
adminAuditSvc  := adminaudit.NewService(adminAuditRepo)
adminAuditHandler := adminaudit.NewHandler(adminAuditRepo)
// передаётся в audit, dashboard, auth, internaldb handlers
admin.HandleFunc("/admin-events", adminAuditHandler.List).Methods("GET")
```

## Тесты

- `adminaudit/service_test.go` — 4 теста (marshal metadata, no metadata,
  nil repo no-op, repo error fail-open).
- `audit/handler_test.go` — 2 новых теста:
  `List_RecordsAdminEvent` (filters в metadata),
  `Status_RecordsAdminEvent` (resource=audit_status).
- `auth/erasure_handler_test.go` — существующие 8 прошли regression
  (сигнатура NewHandler изменена).

Всего: **+6 новых тестов**, regression зелёный для 25+ существующих.

## Размышления

- **Sync vs async writes.** Admin actions редкие (N per day на
  deploy), задержка ~ms не критична. Async добавил бы worker +
  dropped-counter metric + complexity без value.
- **actor_user_id ON DELETE SET NULL.** Если admin был erased через
  DSAR (PR-B), его admin events остаются — audit trail не теряется,
  только actor становится "unknown".
- **`target_id` как VARCHAR(255), не UUID.** Для internaldb source
  это имя (non-UUID); для user erasure — UUID. Unified string.
- **Почему internaldb ADMIN не в audit_logs.** admin CRUD source —
  control-plane (меняет config). Обычный user query к internaldb
  остался в audit_logs (это LLM-traffic-like, retention тот же).
- **`GET /api/internal-dbs/query` не в admin-events.** По совету
  ревью — это analyst path, не admin. Оставлен в audit_logs. Если
  позже analyst тоже станет subject'ом admin-audit — отдельный PR.
- **No retention/purge для admin_event_logs (пока).** Admin events
  обычно нужно хранить дольше user traffic. Retention — PR-D.1.
- **Failure path для CLI purge пишет event.** Оператор видит что
  попытка была (и почему failed). Без этого admin-audit trail
  неполный.

## Definition of Done

- [x] Migration 010 + domain.AdminEvent.
- [x] `adminaudit` package (repository + service + handler) + 4 unit tests.
- [x] `GET /api/admin-events` admin-only route.
- [x] audit.Handler.List/Status wire + 2 tests.
- [x] dashboard 3 endpoint'а wire.
- [x] auth.Handler.EraseUser wire (success + failure paths).
- [x] cmd/audit-purge CLI + embedded scheduler event logging.
- [x] internaldb.Handler.auditAdminRequest → adminaudit (миграция
      с audit_logs).
- [x] `go test ./...` зелёный.

## Что OUT of scope

- Retention/purge для admin_event_logs (PR-D.1).
- Tenant-scoped admin-event filters.
- Alerting on anomalous admin activity (сторонняя SIEM).
- `GET /api/internal-dbs/query` в admin-events (policy decision).
- `POST /api/auth/login` failures в admin-events (auth-failures
  обычно в отдельный security-audit).

## Операционный runbook

### Просмотр admin activity

```
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$URL/api/admin-events?limit=50" | jq

# Только erase-operations:
curl -H ... "$URL/api/admin-events?action=erase&resource=user"

# Кто читает /audit/logs:
curl -H ... "$URL/api/admin-events?action=read&resource=audit_logs"
```

### Расследование инцидента

1. Найти IP/actor: `SELECT DISTINCT actor_user_id FROM admin_event_logs
   WHERE created_at > X`.
2. Посмотреть sequence: `SELECT * FROM admin_event_logs
   WHERE actor_user_id = 'X' ORDER BY created_at`.
3. Корреляция с audit_logs: `... WHERE action='erase' AND target_id = 'Y'`
   → `SELECT * FROM user_erasure_runs WHERE target_user_id = 'Y'`.

## Дальше

- Merge PR-D после review.
- Admin UI для `/api/admin-events` — separate frontend PR.
- Retention для `admin_event_logs` — PR-D.1 (обычно keep 1-2 years
  compliance).
- Anomaly detection (ML/rule-based on admin_event_logs) — roadmap.

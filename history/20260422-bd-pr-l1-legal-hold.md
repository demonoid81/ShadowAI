# PR-L1: Legal Hold groundwork (enterprise v1)

## Контекст
Legal hold — compliance-прерыватель DSAR для user'ов под
судебным/regulatory hold. До PR-L1:
- `§5 Legal Hold` в runbook был `[gap]` — процедура чисто manual.
- `POST /users/{id}/erase` выполнялся БЕЗ проверки hold'а.
- GDPR Art.17(3)(b)/(c)/(e) явно требует carve-out для legal
  obligations — operator обязан вручную избегать DSAR на held
  user'а (fragile).

PR-L1 переводит это в application-layer enforcement.

## Цель
Чтобы на вопрос «могу ли я доказать аудитору, что DSAR запрос на
user'а под судебным hold'ом был БЛОКИРОВАН?» ответ был «да, event
с `blocked_by_hold=true` в admin_event_logs + SIEM mirror».

## Scope (In)

### 1. Migration 013
`backend/migrations-enterprise/013_create_legal_holds.sql`:
- `legal_holds` table: `id, target_user_id, case_ref, reason,
  created_by, created_at, released_at, released_by, is_active`.
- Partial-unique index `idx_legal_holds_active_per_user` —
  максимум один active hold на user.
- Fast lookup index `idx_legal_holds_active_lookup`.
- `target_user_id` имеет `ON DELETE RESTRICT` — user нельзя
  удалить (erasure сама заблокирована, но это двойная защита).

### 2. `internal/legalhold/` (enterprise package)
- `types.go` — `Hold` struct + `HoldChecker` interface.
- `repository.go` — `PGRepository` с методами
  `Create`/`Release`/`HasActiveHold`/`List`. Errors:
  `ErrAlreadyActive`, `ErrNotActive`, `ErrNotFound`.
- `service.go` — `Service` с валидацией (case_ref/reason required),
  fail-closed `HasActiveHold` на nil-Service.
- `handler.go` — admin-only HTTP CRUD:
  - `POST /api/legal-holds` (apply; 201/409/400).
  - `POST /api/legal-holds/{id}/release` (release; 200/404;
    идемпотентно — already_released = 200 с маркером).
  - `GET /api/legal-holds` (list).

### 3. Integration в erasure
- Новое поле `ErasureService.holdChecker` + fluent setter
  `WithHoldChecker(HoldChecker)`.
- В `EraseUser` **перед** `BeginTx` вызывается
  `holdChecker.HasActiveHold`. Если active → возврат
  `ErasureResult{Status: ErasureHoldActive}, nil`. Если checker
  возвращает error → возврат ошибки (fail-closed).
- Новый `ErasureHoldActive = "hold_active"` в `erasure_types.go`
  (core-visible, Apache 2.0).

### 4. HTTP mapping
- `auth/handler.go::EraseUser` мапит `ErasureHoldActive` → HTTP 409.
- Admin event `erase` с `metadata.blocked_by_hold=true` и
  `success=false`.

### 5. Wiring
- `enterprise_wire.go`: создаётся `legalHoldSvc`; передаётся в
  `ErasureService.WithHoldChecker`; `legalHoldHandler`
  регистрирует три маршрута.
- Admin-audit recorder (через `adminAuditRecorder` = fanout PG+SIEM)
  → все `apply_hold` / `release_hold` / `erase_blocked_by_hold`
  события дублируются в SIEM.

### 6. Tests (TDD, `//go:build enterprise`)
- `legalhold/service_test.go` — 9 тестов (happy, missing fields,
  duplicate, release flow, idempotency, not-found, has-active,
  repo-error, nil-service fail-closed, list).
- `legalhold/handler_test.go` — 10 тестов (happy create, non-admin,
  unauthenticated, duplicate 409, validation 400, release happy,
  idempotent release, release not-found, list).
- `auth/erasure_hold_test.go` — 4 теста (hold blocks, error
  fail-closed, no-checker fallback, fluent setter).
- `auth/erasure_handler_test.go` +1 тест для 409 path.

Всего **24 новых теста**, все зелёные.

## Scope (Out / v2+)
- `PurgeOlderThan` / audit-retention учёт holds. Сейчас operator
  вручную `AUDIT_PURGE_INTERVAL=0` на период длинного hold'а.
- Backup freeze — infra-уровня, manual.
- Query/date-range holds (v1 только per-user).
- 4-eyes approval workflow (каждый apply/release требует второго
  approver) — §5.5 roadmap.
- Auto-release через external signal (legal CMS webhook).

## Acceptance criteria
- [x] Held user'а нельзя erase'ить — `EraseUser` возвращает
      `ErasureResult{Status:hold_active}`, handler → 409.
- [x] Release снимает блокировку, повторный erase проходит.
- [x] Все hold actions (apply/release/attempted-blocked-erase)
      пишутся в `admin_event_logs` (и через fanout — в SIEM).
- [x] Core + enterprise builds компилируются чисто.
- [x] `go test ./...` и `go test -tags enterprise ./...` зелёные.

## Проверка

```bash
cd backend
# Unit tests нового пакета:
go test -tags enterprise ./internal/legalhold -v -count=1

# Integration в auth (erasure 409 path + hold check в ErasureService):
go test -tags enterprise ./internal/auth -run "Hold|Erasure" -v

# Full regression matrix:
go test ./... -count=1                     # все core пакеты green
go test -tags enterprise ./... -count=1    # все enterprise green
```

Ручная проверка (после deploy с enterprise tag + migration 013):
```bash
# 1. Create user, apply hold.
curl -X POST -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"target_user_id":"u-target","case_ref":"LEG-001","reason":"SEC inquiry"}' \
  http://localhost:8080/api/legal-holds
# → 201 { "id":"...","is_active":true,... }

# 2. Try DSAR:
curl -X POST -H "Authorization: Bearer $ADMIN" \
  http://localhost:8080/api/users/u-target/erase
# → 409 { "user_id":"u-target","status":"hold_active" }

# 3. Check admin events:
psql "$DATABASE_URL" -c "
  SELECT action, resource, success, metadata->>'blocked_by_hold' AS blocked
  FROM admin_event_logs
  WHERE target_id='u-target'
  ORDER BY created_at DESC LIMIT 5;"

# 4. Release hold:
curl -X POST -H "Authorization: Bearer $ADMIN" \
  http://localhost:8080/api/legal-holds/{id}/release
# → 200 { "id":"...","is_active":false,"released_at":"..." }

# 5. Retry DSAR:
curl -X POST -H "Authorization: Bearer $ADMIN" \
  http://localhost:8080/api/users/u-target/erase
# → 200 { "status":"completed", "audit_rows_scrubbed":N, "budgets_deleted":M }
```

## Риски / допущения
- **Fail-closed на error** — если PG недоступна для
  `HasActiveHold` check, erasure отвергается с 500. Это
  сознательный trade-off: лучше undo'able pause DSAR на 2
  минуты, чем случайно erase'нуть held user'а.
- **Hold-block применяется до `BeginTx`** — не в транзакции с
  `FOR UPDATE`. Race: apply_hold прямо в момент начала erasure
  tx может пропустить block. Acceptable: race-window миллисекунды;
  apply_hold — редкая операция; есть `ON DELETE RESTRICT` на
  `target_user_id` как второй барьер (если user удалился — FK
  в legal_holds сломает constraint).
- **Manual audit-retention**: длинный hold без приостановки
  `AUDIT_PURGE_INTERVAL` может вычистить audit rows по retention.
  На v1 это ответственность operator'а; §5.5 roadmap включает
  автоматический учёт.

## History
- Plan: этот файл.
- Examples: `20260422-bd-pr-l1-examples.md`.

## Next roadmap
1. **SIEM v1.1** — Syslog/OTel/batching (следующий incremental
   improvement).
2. **Legal hold v2** — retention-aware purge, 4-eyes, query/date
   scope.
3. **G2 role-based governance** — product differentiation.
4. **WORM primary storage** — tamper-evident trail (heavy).
5. **Firewall/runtime track** — semantic_v2 rollout, PR-7 streaming.

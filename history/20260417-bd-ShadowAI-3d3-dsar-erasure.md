# bd-ShadowAI-3d3: PR-B — DSAR / Erasure Workflow

**Дата:** 2026-04-17
**Статус:** реализовано.

## Контекст

PR-A закрыл privacy gate на ingest-стороне (payload modes + retention
+ purge). Но **существующая база накопленных данных** оставалась
уязвимой для GDPR/CCPA erasure-запросов: нельзя удалить пользователя,
сохранив operational-аналитику.

PR-B вводит admin-only erasure-flow: обезличить audit trail данного
user'а + удалить user-scoped данные + удалить саму user-row в одной
DB-транзакции. Идемпотентный, с history-trail для compliance audit.

## Контракт

### API

`POST /api/users/{id}/erase` (admin-only, из-за `admin.Use` middleware).

### Status values

- `completed` → 200: erasure выполнен, поля `audit_rows_scrubbed` и
  `budgets_deleted` наполнены.
- `already_erased` → 200: повторный вызов на уже удалённого user'а.
  Идемпотентность через `user_erasure_runs` tombstone-table.
- `not_found` → 404: user не существует И не был erased ранее.

### Что обезличивается в `audit_logs`

```sql
UPDATE audit_logs SET
  user_id = NULL,
  request_body = NULL,
  response_body = NULL,
  shadow_decisions_json = NULL,
  pii_types = NULL
WHERE user_id = $1;
```

**Сохраняется** (для сохранения aggregate-аналитики):
`status_code`, `model`, `provider`, `endpoint`,
`prompt_tokens`, `completion_tokens`, `total_tokens`, `cost_usd`,
`policy_action`, `duration_ms`, `created_at`.

**Полностью удаляется** (user-owned):
- `users` row
- `budgets` row (UNIQUE на `user_id`)

### Транзакция

Вся последовательность в одной `BEGIN ... COMMIT`:
1. `SELECT ... FOR UPDATE` блокирует user-row (защита от concurrent erase).
2. Если user нет — проверка `user_erasure_runs` → `already_erased` или `not_found`.
3. `UPDATE audit_logs` (scrub).
4. `DELETE FROM budgets WHERE user_id = $1`.
5. `DELETE FROM users WHERE id = $1`.
6. `INSERT INTO user_erasure_runs` (tombstone + counters).

Любая ошибка → `ROLLBACK`, БД не изменяется.

## Реализация

### Migration 009 (`user_erasure_runs`)
- `target_user_id UUID NOT NULL` — **не FK**, чтобы tombstone выжил
  удаление самого user'а.
- `initiated_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL` —
  admin, запустивший. Если он потом будет erased — поле станет NULL,
  tombstone всё равно остаётся.
- `audit_rows_scrubbed`, `budgets_deleted` — counters для audit.
- Индексы: по `target_user_id` (lookup при repeat) и `completed_at DESC`.

### `domain/erasure_run.go`
Struct с optional pointers для `initiated_by_user_id` и `notes`.

### `audit/repository.go::ScrubUserDataTx`
Принимает `*sql.Tx` (atomicity с остальными шагами). `UPDATE audit_logs ...`.

### `budget/repository.go::DeleteByUserIDTx`
Аналогичный tx-вариант.

### `auth/erasure.go`
- `ErasureStatus` enum: `completed|already_erased|not_found`.
- `ErasureResult` — JSON response shape.
- Interfaces `AuditScrubber`, `BudgetDeleter` — обеспечивают
  testability (пакет audit + budget implementat'ят).
- `ErasureService.EraseUser(ctx, actorID, targetID)` — orchestration.
  Actor → `user_erasure_runs.initiated_by_user_id`. Если `actor==target`
  (self-erase), поле NULL (user которого удаляем не может "инициировать"
  сам себя в FK-стиле).

### `auth/handler.go::EraseUser`
- Unauth → 401.
- Non-admin → 403.
- eraser=nil (не сконфигурирован) → 503 (явно: "feature off", не 500).
- Empty `{id}` → 400.
- `status=not_found` → 404, остальные 200.
- Detail error не leak'ается (common "erasure failed" message).

### `cmd/shadowai/main.go`
- `auth.NewErasureService(db, auditRepo, budgetRepo)` — DI в main.
- `admin.HandleFunc("/users/{id}/erase", authHandler.EraseUser).Methods("POST")`.

### Тесты (`erasure_handler_test.go`)
8 unit-тестов через `stubEraser`:
- completed → 200 + counters.
- already_erased → 200.
- not_found → 404.
- non-admin → 403 (eraser не вызван).
- unauthenticated → 401.
- eraser=nil → 503.
- runtime error → 500 без leak деталей.
- missing ID → 400.

Integration (live DB) test отдельно — оператор/CI с Postgres.

## Runbook (для оператора)

### Выполнить DSAR erasure

```bash
# 1. Авторизоваться как admin.
TOKEN=$(curl -s -X POST /api/auth/login \
  -d '{"email":"admin@example.com","password":"..."}' | jq -r .token)

# 2. Выполнить erasure.
curl -X POST https://shadowai.example.com/api/users/$USER_ID/erase \
  -H "Authorization: Bearer $TOKEN"

# 3. Проверить результат.
# Ожидаемый 200 response:
# {"user_id":"...","status":"completed","audit_rows_scrubbed":123,"budgets_deleted":1}
```

### Проверить historic erasure

```sql
SELECT target_user_id, completed_at, audit_rows_scrubbed, budgets_deleted
FROM user_erasure_runs
ORDER BY completed_at DESC
LIMIT 10;
```

### Что _не_ удаляется

- Aggregated metrics (`status_code`, `tokens`, `cost_usd`,
  `policy_action`) — для product/ops-аналитики без привязки к человеку.
- Logs в файловой системе / Loki / Datadog — вне scope DB-erasure.
  Если нужен полный erasure через все storage — отдельный runbook
  (PR-B.1 roadmap).
- Backups — DB-backup containing user могут жить по retention
  внешнего backup-storage. Compliance owner должен учитывать это
  в response времени DSAR (обычно 30 дней — достаточно для backup
  rotation).

## Размышления

- **Scrub vs hard delete для audit.** Hard DELETE теряет aggregate.
  Anonymize сохраняет metadata без персональной связи — стандартный
  GDPR-approach. Остаётся ли это "persistent data about identifiable
  person"? Нет: после NULL user_id и scrub bodies строка не позволяет
  идентифицировать human.
- **user_erasure_runs без FK на target_user_id.** Осознанное
  нарушение referential integrity ради tombstone. Без него
  идемпотентность невозможна после hard DELETE FROM users.
- **initiated_by как FK SET NULL.** Admin тоже может быть erased;
  tombstone не должен сломаться тогда.
- **No backfill tombstone.** Существующие users до PR-B не имеют
  записей в `user_erasure_runs`. Первый erase создаст запись, repeat
  call найдёт её.
- **503 vs 500 для eraser=nil.** 503 = "feature off", оператор знает
  что проблема в конфигурации (не запущен ErasureService), не в
  DB-runtime. Deployment с включенным erasure (production) всегда
  имеет valid eraser.

## Definition of Done

- [x] Migration 009.
- [x] Domain `ErasureRun`.
- [x] `audit.Repository.ScrubUserDataTx` + `budget.Repository.DeleteByUserIDTx`.
- [x] `auth.ErasureService` с transaction.
- [x] `auth.Handler.EraseUser` + admin route.
- [x] 8 unit-тестов; `go test ./...` зелёный.
- [x] Operator runbook (этот файл).

## Out of scope (roadmap)

- Tenant-level erase (когда появится `tenant_id`).
- External storage erasure (logs, backups, vector store для
  embeddings). PR-B.1.
- Self-service erasure (сейчас только admin).
- Export/portability (GDPR Article 20).
- Access-audit: кто читал/удалял чьи данные.
- SCIM / SSO integration.

## Acceptance criteria

- [x] admin может выполнить erase через `POST /api/users/{id}/erase`.
- [x] после erase user-row удалена, audit-rows scrubbed, budgets
      удалены (single transaction).
- [x] повторный вызов → `already_erased`.
- [x] unknown user → `not_found` (404).
- [x] non-admin → 403.
- [x] aggregate dashboards не ломаются (scrubbed rows имеют
      NULL user_id, но остальные поля сохранены).
- [x] `user_erasure_runs` содержит запись с target/actor/counters.

## Дальше

Rollout-вопросы:
1. После merge: admin UI должен получить кнопку "Erase user" на
   странице пользователя (frontend-PR).
2. Compliance/legal должны задокументировать SLA (обычно GDPR: 30 дней
   на ответ).
3. External storage erasure — отдельный PR, когда станет актуально.

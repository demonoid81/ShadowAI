# PR-G0: user-read access audit (GET /api/users/{id})

**Дата:** 2026-04-21
**Статус:** реализовано.
**Направление:** enterprise / self-host (см.
`20260421-direction-enterprise-self-host.md`).

## Контекст

`docs/privacy-ops-runbook.md §8.5` зафиксировал gap:

> GET `/api/users/{id}` (полный user object с email) пока НЕ пишется
> в admin_event_logs. Это prerequisite для "read-trail at PII
> granularity".

Для regulated enterprise это compliance blocker — любое admin-reads
PII должно быть аудировано. PR-G0 закрывает gap маленьким, изолированным
изменением без licensing implications (вот почему этот PR идёт
перед licensing session).

## Контракт

- `GET /api/users/{id}` пишет запись в `admin_event_logs`:
  - `action = "read"`
  - `resource = "user"`
  - `target_id = {id}`
  - `actor_user_id` — из JWT claims (admin middleware gated endpoint).
  - `status` = 200 (success) / 404 (not found).
  - `success` = true для 2xx, false иначе.
  - `metadata`:
    - success: `{"target_role": "<role>"}` — только роль, **не email**.
    - 404: `{"error": "user not found"}`.

## Privacy границы

- **Email НЕ попадает в `admin_event_logs.metadata_json`.**
  Admin уже прочитал email в response — дублировать его в audit trail
  размывает PII surface. `target_id` (UUID) + `target_role` достаточно
  для forensic-query "кто когда читал role=admin?".
- Password, api_key, bcrypt hash не попадают (не в scope metadata).
- Regression-guard тест `TestRecordUserRead_CurrentMetadataShape`
  проверяет отсутствие ключей `email`/`password`/`api_key`.

## Реализация

### `internal/auth/handler.go`
- `GetUser` дополнен вызовом `recordUserRead` в двух точках:
  - success path (после `writeJSON(200, user)`);
  - not-found path (после `writeJSON(404, ...)`).
- Новый приватный метод `recordUserRead(r, targetID, status, success, metadata)`:
  - nil-safe при `adminAudit=nil`;
  - извлекает actor из JWT claims (nil если отсутствуют);
  - вызывает `adminAudit.Record` с правильным shape.

### Тесты
`internal/auth/user_read_audit_test.go` (+4):

1. `TestRecordUserRead_NilRecorder` — no-op безопасен.
2. `TestRecordUserRead_WritesEvent` — happy path: actor/target/
   metadata/status.
3. `TestRecordUserRead_UnauthenticatedActor` — без claims actor=nil,
   event всё равно пишется (forensic-сигнал).
4. `TestRecordUserRead_CurrentMetadataShape` — regression-guard на
   отсутствие email/password/api_key в metadata.

## Размышления

- **Почему не UpdateUser в том же PR.** Scope boundary: PR-G0 строго
  про read-path (§8.5). `UpdateUser` — write-path, семантически
  другое (`action=update, resource=user`), может потребовать разных
  metadata-правил (что менялось?). Отдельный PR-G0.1 если нужно.
- **Почему только GetByID, а не ListUsers тоже.** `ListUsers` тоже
  возвращает PII (email, role). По той же логике `§8.5` прикрыл бы
  и его. Но ListUsers возвращает массив — metadata растёт. Отдельный
  PR-G0.2.
- **Integration test через HTTP.** `auth.Service` — concrete, не
  interface; без DB нельзя прогнать full GetUser path. Unit-тесты
  покрывают hotpath-helper. Integration — через live PG в отдельной
  CI-job (not blocking merge).
- **bd создание пропущено.** `bd create` вернул "no beads database
  found" — текущий branch не имеет `.beads` инициализированного.
  Track'ю в этом history file вместо bd.

## Definition of Done

- [x] `GetUser` пишет admin event в success и not-found paths.
- [x] `recordUserRead` nil-safe.
- [x] Email/password/api_key НЕ в metadata (regression-guard).
- [x] 4 unit-теста; все проходят.
- [x] `go test ./...` — зелёный.
- [x] Ни одно утверждение в `docs/privacy-ops-runbook.md` не нарушено;
      §8.5 переходит из `[planned]` в `[implemented]` (отдельный
      docs-commit, или вместе в этом PR).

## Обновление runbook

Нужно: `docs/privacy-ops-runbook.md §8.5` поправить:
- Было: `[planned]` обернуть `authHandler.GetUser` вызовом
  `recordAdminRead`.
- Станет: `[implemented]` GET `/api/users/{id}` пишет в
  `admin_event_logs` с `action=read, resource=user, target_id={id}`.
  Gap UpdateUser/ListUsers остаются как `[planned]`.

## Следующий шаг

Согласно direction-decision
(`20260421-direction-enterprise-self-host.md`):
1. Licensing decision — отдельной сессией, до PR-G1.
2. PR-G1: Provider/Model Governance (allowlist + deny-by-default +
   audit).

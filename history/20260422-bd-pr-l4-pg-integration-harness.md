# PR-L4: Targeted PostgreSQL concurrency harness для PR-L3 proof

## Контекст
PR-L3 ввёл advisory-lock coordination между `apply_hold` и
`PurgeOlderThanRespectingHoldsAndRecordRun`. Unit-tests не могут
доказать PG-уровневую семантику (MVCC, advisory lock). PR-L4 даёт
integration harness — live PG через testcontainers-go для
концентрированного proof.

Scope узкий: **ТОЛЬКО PR-L3 commit-order guarantee**. НЕ общий
integration framework.

## Scope (In)

### Harness
- Новый пакет `backend/integration/` под
  `//go:build enterprise && integration`.
- `harness_test.go`:
  - `startPostgres(t)` — поднимает `postgres:16-alpine`
    testcontainer. Skip если Docker недоступен (dev/CI без
    Docker просто пропускает, не fail).
  - `applyAllMigrations(t, db)` — глобально sortedly
    применяет `backend/migrations/001-008` + `backend/migrations-
    enterprise/009-014`.
  - Helpers: `insertTestUser`, `insertAuditLog`, `auditLogExists`.

### Tests (3)
- `TestCoord_HoldBeforePurge_RowsProtected` — CASE A из PR-L3
  contract: apply_hold commit → purge commit → rows защищены.
  `audit_purge_runs` row записан (coordinated path включает
  RecordRun в тот же tx).
- `TestCoord_PurgeBeforeHold_RowsDeleted` — CASE B: purge commit
  → apply_hold commit → удаление допустимо (hold не существовал
  на момент purge).
- `TestCoord_MixedUsers` — regression: в одном purge-tick'е
  строки held-user'а защищены, free-user'а удалены.

### Build + run contract
- Обычный `go test ./...` — без Docker, integration tests
  исключены build tag'ом.
- Обычный `go test -tags enterprise ./...` — тоже без Docker,
  integration tests всё ещё требуют второй tag.
- `go test -tags 'enterprise integration' ./integration -count=1` —
  запускает integration tests (требует Docker).
- `startPostgres` даёт `t.Skip` (не Fail) если Docker
  недоступен — CI without Docker просто пропускает suite.

### Deps
- `go get github.com/testcontainers/testcontainers-go`
- `go get github.com/testcontainers/testcontainers-go/modules/postgres`
- go.mod получил transitive closure (testcontainers + opentelemetry
  и т.п.). Core/Enterprise binary size не изменился —
  integration-пакет не линкуется в main build'е (build tag).

## Scope (Out)
- CI wiring — отдельный project task (GitHub Actions / gitlab
  CI matrix).
- MySQL / SQLite поддержка — не нужно, продакт only PostgreSQL.
- Общий integration harness для всех packages — отдельный
  initiative (если появятся firewall / proxy integration tests).
- L2.3 (4-eyes), G3 (scope wider), WORM, SIEM v1.1 — следующие PR.

## Live PG validation (runtime proof)

Прогон на локальном docker:
```
=== RUN   TestCoord_HoldBeforePurge_RowsProtected
--- PASS: TestCoord_HoldBeforePurge_RowsProtected (5.34s)
=== RUN   TestCoord_PurgeBeforeHold_RowsDeleted
--- PASS: TestCoord_PurgeBeforeHold_RowsDeleted (4.78s)
=== RUN   TestCoord_MixedUsers
--- PASS: TestCoord_MixedUsers (4.75s)
PASS
ok  	github.com/shadowai/backend/integration	15.26s
```

## Acceptance
- [x] Оба commit-order сценария PR-L3 детерминистично
      воспроизводятся и passing.
- [x] `hold-before-purge` сохраняет evidence (deleted=0,
      row exists).
- [x] `purge-before-hold` удаляет (deleted=1, row absent); late
      apply_hold всё ещё OK.
- [x] Coordinated path пишет `audit_purge_runs` внутри того же
      tx (проверено прямым SELECT после purge).
- [x] `go test ./...` + `go test -tags enterprise ./...`
      остаются быстрыми и без Docker.
- [x] Integration tests требуют explicit `-tags 'enterprise
      integration'`.

## Проверка
```bash
cd backend
# Regular suites (no Docker):
go test ./... -count=1
go test -tags enterprise ./... -count=1

# Integration suite (Docker required):
go test -tags 'enterprise integration' ./integration -count=1
```

Timeout note: integration tests ~5s each (контейнер startup
+ migrations). Setting `-timeout=180s` рекомендовано для
defensive margin.

## Риски / допущения
- **Docker dependency** — integration suite требует Docker
  daemon. CI без Docker получит skipped-tests (не failures).
- **Migration apply order** — lex-sort по basename работает
  пока имена стартуют с 3-digit prefix. Если когда-то появятся
  `010a_*`, `010b_*` коллизии — harness можно обогатить, но
  scope PR-L4 этого не трогает.
- **Concurrent scenarios → sequential proof**: tests sequential
  (commit A ↔ затем commit B). Advisory lock serialize
  concurrent случай — sequential достаточно для контракта
  PR-L3 ("кто commit'ит раньше"). Полноценный race-window
  test (goroutines с timing) — next-level validation, не
  нужен для текущего contract.

## History
- Plan: этот файл.
- Proves: PR-L3 commit-order guarantee (apply_hold ↔ purge).

## Next
1. ✅ PR-L4 — targeted PG harness.
2. **L2.3** — 4-eyes approver workflow.
3. WORM / SIEM v1.1 / G2.2 / G3 / Firewall-runtime.

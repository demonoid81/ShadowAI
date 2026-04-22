# PR-L2.1: Race-fix retention-aware purge + runbook scope

## Контекст
Review PR-L2 — два finding'а.

1. **Medium** — snapshot-delete race. PR-L2 сначала читал
   `legalHoldSvc.ActiveUserIDs()`, потом вызывал
   `PurgeOlderThanExcept(..., heldUserIDs)`. Hold, applied между
   этими двумя шагами, не защитит свои rows на текущем
   scheduler-tick'е — эти rows (если они старше cutoff'а)
   удалятся. Для evidence-preservation semantics это subtle
   compliance-риск.

2. **Low** — runbook contradict. §5.3 говорит manual pause для
   длинных hold'ов, §8.2 говорит "retention-aware implemented".
   Нужно scope'нуть manual pause явно к Core-only CLI path.

## Scope (In)

### Fix #1: Single-SQL race-free purge
- Новый метод `audit.Repository.PurgeOlderThanRespectingHolds`
  в отдельном файле `retention_hold.go` под
  `//go:build enterprise`. SQL:
  ```sql
  DELETE FROM audit_logs WHERE id IN (
    SELECT id FROM audit_logs
    WHERE created_at < $1
      AND (user_id IS NULL OR NOT EXISTS (
        SELECT 1 FROM legal_holds lh
        WHERE lh.is_active = true
          AND lh.target_user_id = audit_logs.user_id
      ))
    LIMIT $2
  )
  ```
- PG MVCC даёт snapshot-isolated read legal_holds в момент
  row-scan'а. Hold applied после начала statement'а защитит
  свои rows в DELETE scan без user-level race.
- Scheduler в `enterprise_wire.runAuditPurgeScheduler` перешёл
  с `PurgeOlderThanExcept(..., heldUserIDs)` на
  `PurgeOlderThanRespectingHolds(...)`. `heldUserIDs` snapshot
  остаётся для `metadata.holds_excluded` (forensic display
  only; race в count acceptable — correctness в DELETE не
  зависит от snapshot).
- Scheduler делает type-assert `auditSvc.GetRepo().(*audit.Repository)`,
  т.к. `PurgeOlderThanRespectingHolds` — enterprise-only метод
  на concrete `*Repository`, не в `audit.Repo` interface.

### Fix #2: Runbook §5.3 scope
- §5.3 пункт 5 "Audit-retention" переписан:
  - Enterprise build + scheduler: `[implemented]` (PR-L2.1),
    manual pause НЕ требуется.
  - Core-only CLI / внешний cron-wrapper: `[manual]`, operator
    обязан остановить CLI или предоставить exclusion-wrapper.
- §8.2 bullet обновлён: упоминает single-SQL race-free подход
  PR-L2.1.
- Changelog 1.13 добавлен.

## Scope (Out)
- Полная поддержка Core CLI: operator Core-билда legal_holds
  не видит (package enterprise-only). Остаётся manual.
  Переработка Core CLI под hybrid scope — отдельный roadmap
  item (low priority, Core rarely deploy'ится для regulated
  enterprise без enterprise tag).
- Integration test с реальным PostgreSQL для
  `PurgeOlderThanRespectingHolds`. Текущий test matrix — только
  unit-level. `uuidArrayLiteral` покрыт unit'ом; SQL сам —
  требует PG (можно через dockertest / testcontainers).
  Оставлено как осознанный residual risk, т.к. проект в целом
  не имеет PG integration-harness; вводить его отдельной задачей.

## Tests
- Существующие `TestUUIDArrayLiteral`, `TestActiveUserIDs_*`
  продолжают работать (не изменялись).
- Build verification: `go build ./...` + `go build -tags
  enterprise ./...` чистые.
- `go test ./... -count=1` + `go test -tags enterprise ./...
  -count=1` — core + enterprise matrix green.
- Regression test для single-SQL SQL-path не добавлен — требует
  реальной PG (см. Scope Out).

## Acceptance
- [x] Race устранён на correctness-уровне (single-SQL
      consults legal_holds).
- [x] Scheduler использует новый race-free метод.
- [x] metadata.holds_excluded продолжает writе (forensic only).
- [x] Core CLI path не затронут (backward compat).
- [x] Runbook §5.3 scope'нут; §8.2 обновлён; changelog 1.13.
- [x] Core + enterprise matrix green.

## Проверка
```bash
cd backend
go build ./... && go build -tags enterprise ./...
go test ./... -count=1
go test -tags enterprise ./... -count=1
```

Ручная (после deploy enterprise + migration 013):
```bash
# 1. Create hold.
curl -X POST -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"target_user_id":"<uuid>","case_ref":"LEG-1","reason":"r"}' \
  http://localhost:8080/api/legal-holds

# 2. Run scheduler tick (wait for AUDIT_PURGE_INTERVAL или
# вручную вызвать). Проверить в логах:
# "audit-purge scheduler: deleted N rows (cutoff=..., holds_excluded=1)"
# "rows for held user удержаны в audit_logs (даже если старше cutoff)".

# 3. Release hold. На следующем tick'е rows становятся eligible.
```

## Риски / допущения
- **Type-assert brittleness**: scheduler type-asserts
  `Repo.(*audit.Repository)`. Если в будущем operator подсунет
  другой `audit.Repo` implementation (unusual), scheduler
  logs error + exits. Fail-closed — в enterprise prod всегда
  используется concrete `*audit.Repository`.
- **No PG integration test**: корректность single-SQL
  полагается на code review + PG MVCC semantics. Отдельный
  integration-harness — roadmap item.
- **Snapshot race в metadata**: `holds_excluded` count берётся
  из snapshot-шага. Если hold applied между snapshot и DELETE,
  count не учтёт этот hold — UI/SIEM покажет +0 для одного
  tick'а. Correctness не зависит.

## History
- Plan: этот файл.
- Related: PR-L2 (first-pass retention-aware).

## Roadmap (без изменений)
1. **L2.2** — 4-eyes approver workflow.
2. **L3** — hold-scope wider (query-window, date-range).
3. **Integration-harness** — real-PG tests для purge SQL.
4. **WORM**, **SIEM v1.1**, **G2.2 caching**, **G3**,
   **Firewall/runtime**.

# PR-L3: Advisory-lock coordination apply_hold ↔ purge

## Контекст
PR-L2.2 честно признал: single-SQL NOT EXISTS не даёт race-free
гарантию под READ COMMITTED. Statement-snapshot устанавливается
в начале DELETE, hold applied позже не защитит rows этого tick'а.

PR-L3 закрывает реальный compliance gap через coordination, а
не через улучшение testability. Выбрано `pg_advisory_xact_lock`,
НЕ SERIALIZABLE:
- Проще reasoning.
- Нет retry-механики.
- Scheduler редкий → coarse lock acceptable.
- Легче объяснить аудитору.

## Scope (In)

### 1. Shared coordination helper
- Новый enterprise-only пакет `backend/internal/legalholdcoord/`.
- Константы `AdvisoryLockNamespace=4201`, `HoldPurgeResource=1`
  (int32 пара → `pg_advisory_xact_lock($1, $2)`).
- Функция `AcquireHoldPurgeLock(ctx, tx) error` — берёт lock в
  переданной tx. Lock освобождается автоматически при
  COMMIT/ROLLBACK.

### 2. apply_hold coordinated
`legalhold.PGRepository.Create`:
1. `BeginTx` → 2. `AcquireHoldPurgeLock(ctx, tx)` →
3. INSERT legal_holds → 4. `Commit`.
Defensive `defer tx.Rollback()` (no-op после Commit).
Интерфейс `Repository.Create` не меняется — coordination
детали скрыты в PG-impl.

### 3. Coordinated purge + record-run
`audit.Repository.PurgeOlderThanRespectingHoldsAndRecordRun`
в `retention_hold.go` (enterprise-only):
1. `BeginTx` → 2. `AcquireHoldPurgeLock` →
3. Chunked DELETE с `NOT EXISTS (FROM legal_holds)` →
4. INSERT audit_purge_runs →
5. `Commit`.
Lock держится весь purge — acceptable для редкого scheduler'а.

### 4. Scheduler simplification
`enterprise_wire.runAuditPurgeScheduler`:
- Interface assertion сменён на `coordinatedHoldPurger`:
  ```go
  interface {
      PurgeOlderThanRespectingHoldsAndRecordRun(ctx, cutoff, chunkSize) (int, error)
  }
  ```
- Mismatch → admin-event `action=scheduler_init_failed,
  error_code=repo_missing_coordinated_hold_purger`.
- Scheduler не вызывает `RecordPurgeRun` отдельно — это теперь
  часть atomic method.
- `heldUserIDs` snapshot остаётся ТОЛЬКО для
  `metadata.holds_excluded` (forensic display; correctness
  защищена lock'ом, не snapshot'ом).

### 5. Docs
- Runbook §8.2 перестроен: `[implemented, partial]` →
  `[implemented]` с commit-order guarantee semantics.
- Runbook §5.3 пункт 5: enterprise scheduler `[implemented]` —
  manual pause НЕ требуется; core CLI остаётся `[manual]`.
- Changelog 1.15.
- ENTERPRISE.md дополнен `legalholdcoord/` package.

## Scope (Out — следующие PR)
- **PR-L4**: PostgreSQL concurrency harness — integration-level
  test concurrent apply_hold + purge, реальный PG. Закроет
  "unit tests не докажут PG concurrency" residual из PR-L2.2.
- **release_hold coordination** — apply/release асимметричны.
  Release снимает lock только для purge-защиты; DSAR-block
  ErasureService уже использует `HasActiveHold`. L3 не
  координирует release → purge — если hold released, его rows
  становятся eligible на следующем tick'е (желаемое поведение).
- **HasActiveHold** — read-only path, tx+lock не нужны.
- **L5 / L6** — 4-eyes approver, hold-scope wider.

## Целевой контракт (формально)

- **Если** `apply_hold` commit завершился **раньше**
  `PurgeOlderThanRespectingHoldsAndRecordRun` commit,
  **то** purge НЕ удалит audit_logs этого user'а.
- **Если** purge commit завершился раньше `apply_hold` commit,
  удаление допустимо: на момент purge hold ещё не существовал
  (correctness compliance-satisfied).

Гарантия строится вокруг commit order, НЕ "кто начал раньше".

## Tests

### Unit (новые)
- `legalholdcoord/lock_test.go` — `TestAdvisoryLockConstants`
  (regression guard на ns/resource literals),
  `TestAcquireHoldPurgeLock_NilTx_ReturnsError` (defence).

### Existing
- `legalhold.Service` тесты продолжают проходить через memRepo
  (in-memory, не использует coord) — service-level contract
  не изменился.
- `audit` тесты не изменились (coordinated метод — отдельный
  entry point, старый `PurgeOlderThan*` сохранён).
- Scheduler-mismatch admin-event capture покрыт через
  существующие wiring стабы (unit-level assertion,
  concurrency-level — задача PR-L4).

### Не покрыто (осознанный scope)
- Реальная concurrency под PG — требует integration harness
  (PR-L4).

## Acceptance
- [x] apply_hold и coordinated purge используют один advisory
      lock (namespace 4201, resource 1).
- [x] Purge делает DELETE + RecordPurgeRun в одной tx.
- [x] Scheduler больше не вызывает отдельный RecordPurgeRun
      outside tx.
- [x] Mismatch repo type → admin-event (не silent log).
- [x] Docs переформулированы: commit-order guarantee.
- [x] Core build не изменился.
- [x] `go build ./...` и `go build -tags enterprise ./...` green.
- [x] `go test ./...` и `go test -tags enterprise ./...` green.

## Проверка
```bash
cd backend
go test -tags enterprise ./internal/legalholdcoord -count=1
go test ./... -count=1
go test -tags enterprise ./... -count=1
```

Ручная в prod (enterprise build + migration 013):
```bash
# 1. Apply hold.
curl -X POST -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" \
  -d '{"target_user_id":"<uuid>","case_ref":"L3-1","reason":"test"}' \
  https://shadowai.example/api/legal-holds

# 2. Observe psql во время purge-tick:
#    SELECT * FROM pg_locks WHERE locktype='advisory';
#    должен показать lock namespace=4201, objid=1.

# 3. Проверить admin events: purge scheduler должен писать
#    success=true с holds_excluded=1.
```

## Риски / допущения
- **Lock-contention**: scheduler редкий (AUDIT_PURGE_INTERVAL
  default 24h); apply_hold редкий. Contention в prod
  negligible.
- **Deadlock-safety**: single-resource advisory lock не
  deadlock-prone сам по себе. Оба вызова берут один lock в
  одном порядке — нет cycle.
- **Decorator compatibility**: structural interface
  `coordinatedHoldPurger` будущий metrics/tracing wrapper
  должен forward'ить метод. Mismatch → scheduler fails-early
  с admin-event.
- **No PG integration test**: корректность полагается на
  PG advisory-lock semantics + code review. PR-L4 закроет.

## History
- Plan: этот файл.
- Related: PR-L1 (hold groundwork), PR-L2 → PR-L2.2
  (narrowing race-window, honest wording), PR-L3 **closes gap**.

## Roadmap (порядок)
1. ✅ **PR-L3** — advisory-lock coordination.
2. **PR-L4** — targeted PG concurrency integration harness.
3. **L2.3** — 4-eyes approver workflow.
4. **WORM** — primary tamper-evident storage.
5. **SIEM v1.1** — syslog/OTel/batching.
6. **G2.2 / G3** — governance caching / department scope.
7. **Firewall/runtime** — semantic_v2 rollout, PR-7 streaming.

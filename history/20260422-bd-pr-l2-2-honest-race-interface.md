# PR-L2.2: Honest race-window wording + structural interface assertion

## Контекст
Review PR-L2.1 указал на два справедливых finding'а:

1. **Medium** — PR-L2.1 неправильно утверждал "race-free".
   PostgreSQL default READ COMMITTED даёт statement-level
   snapshot, установленный в **начале** DELETE-statement'а.
   `NOT EXISTS (... FROM legal_holds ...)` использует этот
   snapshot — hold, applied ПОСЛЕ старта statement'а, не
   виден → его rows могут удалиться в этом же tick'е.
   Race сужен (миллисекунды вместо round-trip snapshot'а
   в Go), но не устранён.

2. **Low** — Scheduler делал concrete type assertion
   `.(*audit.Repository)`. Decorator wrap (metrics, tracing)
   тихо провалит проверку, scheduler молча выйдет с одной
   log-строкой.

## Scope (In)

### Fix #1 — honest wording

Три места формулировок ослаблены с "race-free" до "narrows race
window":

- `backend/internal/audit/retention_hold.go` — package header +
  comment на `PurgeOlderThanRespectingHolds`. Явно описан
  residual race-window (READ COMMITTED statement-level snapshot),
  path'ы к true race-free (SERIALIZABLE + advisory lock) как
  PR-L3 roadmap.
- `backend/cmd/shadowai/enterprise_wire.go` — scheduler comment.
  Указано что AUDIT_PURGE_INTERVAL должен быть сильно больше
  времени apply_hold round-trip'а (default values это покрывают).
- `docs/privacy-ops-runbook.md` §5.3 пункт 5 + §8.2 —
  статус `[implemented]` уточнён до `[implemented, partial]`,
  описан residual window, mitigation (apply hold задолго до
  cutoff), roadmap path (PR-L3).

### Fix #2 — structural interface assertion

- Заменил `.(*audit.Repository)` на anonymous interface
  `holdAwarePurger { PurgeOlderThanRespectingHolds(...);
  RecordPurgeRun(...) }`.
- Decorator-friendly: любая future metrics/tracing обёртка
  автоматически satisfies если forward'ит оба метода.
- На fallback (interface НЕ реализован) пишется admin-event
  `action=scheduler_init_failed, error_code=repo_missing_hold_aware_method`
  вместо silent log-line. Operator увидит проблему через SIEM.

## Scope (Out)

- **True race-free design** (PR-L3 coordination):
  - Option A: SERIALIZABLE isolation на DELETE + apply_hold
    retry loop. Дороже по lock contention, но PostgreSQL native.
  - Option B: advisory lock. apply_hold и purge оба берут
    `pg_advisory_xact_lock(hash("legal_hold"))` — strict mutex.
    Performance-impact на apply_hold (acceptable, apply редкий).
- **Integration test** для PostgreSQL с concurrent apply_hold
  + purge — требует test-harness (dockertest/testcontainers),
  отдельный roadmap.

## Tests
- Full test matrix green: `go test ./... -count=1` и
  `go test -tags enterprise ./... -count=1`.
- Новые тесты не добавлены: изменения этого PR —
  documentation + interface-shape refactor (unit-coverage
  существующих tests достаточен).

## Acceptance
- [x] Формулировки "race-free" заменены на честные "narrows race
      window" / "partial" в коде, комментариях и runbook.
- [x] Residual race-window (READ COMMITTED statement snapshot)
      задокументирован explicitly.
- [x] Roadmap-path'ы (SERIALIZABLE / advisory lock, PR-L3)
      упомянуты.
- [x] Scheduler использует structural interface assertion.
- [x] Fallback на missing interface пишет admin-event (не silent).
- [x] Core + enterprise builds green.
- [x] Test matrix полностью green.

## Проверка
```bash
cd backend
go build ./... && go build -tags enterprise ./...
go test ./... -count=1
go test -tags enterprise ./... -count=1
```

## Риски / допущения
- **Не fix'ит fundamental race** — это осознанный scope PR-L2.2.
  True race-free = PR-L3.
- **Decorator pattern not yet exercised** — interface-based
  assertion — future-proofing. Unit coverage на fallback
  path не добавлен (trivial defensive code, admin-event
  capture — ручная проверка в staging).

## History
- Plan: этот файл.
- Related: PR-L2 (initial retention-aware), PR-L2.1 (first
  race-window narrowing).

## Roadmap
1. **PR-L3** — true race-free coordination (advisory lock /
   SERIALIZABLE).
2. **PR-L4** — integration-harness с real PostgreSQL.
3. **L2.3** — 4-eyes approver workflow.
4. **L2.4 / L5** — hold-scope wider (query-window, date-range).
5. WORM / SIEM v1.1 / G2.2 / G3 / Firewall.

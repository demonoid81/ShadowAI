# PR-L2: Retention-aware audit purge (legal hold v2 compact)

## Контекст
PR-L1 дал DSAR block при active hold, но audit evidence мог
раствориться по retention (audit-purge scheduler не знал про
holds). Это подрывает forensic-ценность hold'а: DSAR отвергнут,
но через 30 дней (default retention) rows старше cutoff'а
удаляются — исчезает то, ради чего hold ставили.

PR-L2 — compact "Legal hold v2": retention-aware purge.
4-eyes approver и hold-scope wider оставлены как отдельные
следующие PR (L2.1 / L3) чтобы не раздувать scope.

## Scope (In)

### 1. Core (Apache) — non-breaking API extension
- `audit.Repository.PurgeOlderThanExcept(ctx, cutoff, chunk,
  exceptUserIDs)` — новый метод. nil/empty exceptUserIDs → старое
  поведение (SQL без WHERE user_id NOT IN).
- `audit.Repository.PurgeOlderThan(...)` остаётся как backward-compat
  обёртка — вызывает новый метод с nil.
- `audit.Repo` interface добавлен `PurgeOlderThanExcept`.
- Helper `uuidArrayLiteral` — безопасно строит Postgres text[]
  literal для ANY($N).
- Core CLI `cmd/audit-purge` продолжает использовать
  `PurgeOlderThan` (backward compat; Core scope не имеет
  legal_holds).

### 2. Enterprise — legalhold.ActiveUserIDs
- `Repository.ActiveUserIDs(ctx) ([]string, error)` — bulk
  lookup для scheduler.
- `Service.ActiveUserIDs` — прокси + fail-closed на nil Service
  (unknown-active → error).
- `PGRepository.ActiveUserIDs` — `SELECT target_user_id::text
  FROM legal_holds WHERE is_active = true`.

### 3. Enterprise — runAuditPurgeScheduler wire
- Перед каждым tick scheduler вызывает
  `legalHoldSvc.ActiveUserIDs(ctx)`.
- Error lookup → skip tick + admin_event с
  `error: "hold_lookup_failed"` (fail-closed).
- Success → `PurgeOlderThanExcept(..., heldUserIDs)`.
- Admin event metadata получает `holds_excluded: N` для
  forensics и SIEM-rules.

## Scope (Out → отдельные PR)
- **L2.1**: 4-eyes approver workflow (apply/release hold
  требует second admin confirm).
- **L3**: hold scope wider — query-window, date-range holds.

## Tests (новых)

### core/audit (1)
- `TestUUIDArrayLiteral` — 6 cases (empty, single UUID, два
  UUID, escape для `"` и `\`). Guard регрессии на safety
  построения Postgres literal.

### enterprise/legalhold (3)
- `TestActiveUserIDs_HappyPath` — 2 active + 1 released,
  released исключён, active возвращены.
- `TestActiveUserIDs_Empty` — чистый deploy, empty list без
  error.
- `TestActiveUserIDs_NilService_FailClosed` — nil Service →
  error (scheduler safeguard против misconfigured wire).

### Test stubs
- `internal/audit/handler_test.go::recordingRepo` — добавлен
  stub `PurgeOlderThanExcept`.
- `internal/proxy/handler_wiring_test.go::captureAuditRepo` —
  аналогично.

## Acceptance
- [x] User под active hold → audit rows НЕ удаляются retention
      scheduler'ом, даже если старше cutoff'а.
- [x] Released hold → user audit rows снова eligible для
      purge на следующем tick'е.
- [x] `PurgeOlderThan` (backward compat) продолжает работать
      для Core build / dev.
- [x] Fail-closed: hold-lookup error → skip tick, admin event
      логируется.
- [x] Admin event содержит `holds_excluded` count для
      forensics / SIEM.
- [x] Core + enterprise builds green.
- [x] Full test matrix green (core + enterprise).

## Проверка
```bash
cd backend
go test ./internal/audit ./internal/legalhold -count=1           # core+enterprise scope tests
go test -tags enterprise ./... -count=1                            # full matrix
go test ./... -count=1                                              # core matrix
```

## Риски / допущения
- **Size of exceptUserIDs**: в prod ожидается O(десятки). PG
  ANY($3::text[]) эффективен на таких размерах, полноценный
  index-scan. Для O(тысячи) — профилировать отдельно (v2.1).
- **Snapshot staleness**: hold apply'нут мгновенно после
  snapshot'а → rows этого user'а в текущем tick'е еще покраснеют
  (удалятся). На следующем tick'е уже защищены. Acceptable:
  tick — короткий (AUDIT_PURGE_INTERVAL default 24h); hold apply
  race-window пренебрежимо мал.
- **Core CLI**: `cmd/audit-purge` продолжает использовать старый
  `PurgeOlderThan`. Core scope по ENTERPRISE.md не имеет
  legal_holds, так что retention-aware применим только в
  enterprise scheduler. CLI operator в enterprise deploy должен
  либо не использовать CLI (только scheduler), либо вручную
  исключать held users.

## History
- Plan: этот файл.
- Related: PR-L1 (legal hold groundwork), PR-L1.1/L1.2/L1.3
  (privacy + secret hardening + core-scope).

## Roadmap
1. **L2.1** — 4-eyes approver workflow.
2. **L3** — hold-scope wider (query-window, date-range).
3. **WORM** — tamper-evident primary storage.
4. **SIEM v1.1** — syslog/OTel/batching.
5. **G2.2** — policy caching для high-traffic.
6. **Firewall/runtime** — semantic_v2 rollout, PR-7 streaming.

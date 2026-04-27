# bd-ShadowAI-ctp — PR-L8.1c query_scope purge enforcement

## Контекст

L8.1b разрешил создание `scope_type=query_scope` legal hold и зафиксировал
selector identity в WORM `legal_hold_events` canonical v2. Остаточный gap:
retention purge учитывал `whole_user` и `date_range`, но не selective
`query_scope`.

CASS-поиск `L8.1c query_scope purge enforcement legal hold` не нашёл прошлых
session-записей. Источники истины: локальный RFC PR-L8, history L8.1b и код
`backend/internal/audit/retention_hold.go`.

## Цель

Сделать active/release_pending `query_scope` holds юридически эффективными для
retention purge: matching `audit_logs` rows сохраняются, non-matching rows
остаются purge-eligible.

## Scope In

- Расширить `PurgeOlderThanRespectingHoldsAndRecordRun`.
- Расширить non-recorded `PurgeOlderThanRespectingHolds`.
- Компилировать stored `scope_query_json` через `legalholdselector`.
- Invalid/corrupt stored selector aborts purge fail-closed до DELETE.
- Писать `admin_event_logs.action=legal_hold_query_scope_compile_failed`.
- Regression integration tests.
- Обновить stale docs по query_scope status.

## Scope Out

- Evidence bundle selector manifest.
- UI selector builder.
- BYOK/KMS encryption для selector JSON.
- `conversation_id` schema.

## План реализации

1. Найти purge path через ast-index.
2. Добавить red integration tests для active/release_pending query_scope и
   corrupted selector.
3. Реализовать preflight load active/release_pending query_scope holds.
4. Динамически добавить selector clauses в DELETE SQL.
5. Добавить compile-failure admin event без raw selector.
6. Обновить docs/history/examples.
7. Прогнать targeted/full checks, закрыть bd, сделать commit.

## Размышления

Рассмотрены варианты: расширить existing `NOT EXISTS legal_holds` под
query_scope или построить отдельный динамический `AND NOT (...)` слой.
Принято решение использовать отдельный слой, потому что selector compiler
генерирует audit-log predicates, а не predicates над `legal_holds`.

Рассмотрены варианты при invalid stored selector: игнорировать только этот hold,
fallback'нуться в `whole_user` или abort purge. Принято решение abort purge
fail-closed: silently ignoring selector creates evidence loss, а fallback в
`whole_user` меняет legal scope без explicit operator action.

Альтернатива логировать raw selector отклонена: selector может раскрывать
forensic strategy. Event содержит только `hold_id`, `selector_hash`,
`selector_version`, `target_user_id` и error summary.

## Definition of Done

- Matching active query_scope row is not purged.
- Non-matching row is purged.
- release_pending query_scope protects matching rows.
- Corrupted stored selector aborts purge and deletes no rows.
- Compile failure writes `legal_hold_query_scope_compile_failed`.
- whole_user/date_range regression remains green.
- Required tests pass.

## Проверка

- `go test -tags 'enterprise integration' ./integration -run 'TestCoord_QueryScope' -count=1`
- `go test -tags 'enterprise integration' ./integration -run 'TestCoord_' -count=1`
- `go test -tags enterprise ./internal/audit ./internal/legalhold ./internal/legalholdselector -count=1`
- `go test -tags enterprise ./... -count=1`
- `go test ./... -count=1`
- `git diff --check`

## Риски / зависимости

- Query-scope purge SQL is security-sensitive; compiler-generated SQL is the
  only accepted dynamic predicate source.
- Fail-closed selector corruption can stop scheduled retention purge until an
  operator fixes/rejects the hold.
- Existing dirty worktree contains unrelated files and must not be staged.

## Roadmap

### v1

- Query-scope runtime purge enforcement.

### v2+

- Evidence bundle selector manifest.
- Optional selector payload encryption/BYOK.

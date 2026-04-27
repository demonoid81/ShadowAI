# bd-ShadowAI-4ue — PR-L8.1b query_scope create + WORM canonical v2

## Контекст

L8.1a добавил безопасный selector foundation для `query_scope`: strict JSON DSL,
normalization, stable hash, SQL preview и fail-closed create path. L8.1b включает
создание `query_scope` legal hold и делает selector identity tamper-evident через
`legal_hold_events` canonical v2.

CASS-поиск по `L8.1b query_scope create WORM canonical v2` не нашёл релевантных
session-записей. Источником истины были локальный код, `bd-ShadowAI-4ue` и
history/RFC L8.1a.

## Цель

Разрешить `POST /api/legal-holds` с `scope_type=query_scope` только после
успешной strict-компиляции selector, сохранить normalized selector в
`legal_holds` и зафиксировать scope/hash/version в append-only
`legal_hold_events` chain.

## Scope In

- `legalhold.Service.CreateQueryScopedHoldInOrg`.
- Handler branch для `scope_type=query_scope`.
- Storage/scans для `scope_query_json`, `scope_query_hash`,
  `scope_query_version`.
- Migration `024_legal_hold_events_scope_v2.sql`.
- `chain.CanonicalLegalHoldEventV2`.
- Verifier dispatch `canonical_version=v1/v2`.
- Тесты create/invalid selector/canonical dispatch/tamper.

## Scope Out

- Query-scoped purge enforcement.
- Evidence bundle selector manifest.
- UI selector builder.
- BYOK/KMS для selector payload.

## План реализации

1. Зафиксировать red tests для create path и WORM canonical v2.
2. Добавить `query_scope` branch в handler без raw selector в admin metadata.
3. Расширить repository insert/scans и `insertHoldEvent` на v2 fields.
4. Добавить enterprise migration для scope fields в `legal_hold_events`.
5. Расширить chain verifier для legacy v1 и new v2 rows.
6. Прогнать targeted, enterprise и core regression.
7. Обновить history/examples, закрыть bd и сделать commit.

## Размышления

Рассмотрены варианты: хранить selector только в `legal_holds` или копировать
его hash в `legal_hold_events`. Принято решение копировать hash/version/scope в
append-only event, потому что `legal_holds` остаётся mutable current-state
таблицей и не является WORM-источником.

Рассмотрены варианты canonical migration: переписать старые events в v2 или
сохранить backward compatibility. Принято решение dispatch по
`canonical_version`: legacy rows остаются `v1`, новые transition rows пишутся
как `v2`.

Альтернатива логировать raw selector в admin audit отклонена: selector может
раскрывать forensic intent и структуру расследования; для SIEM достаточно
`selector_hash`, `scope_type`, `matched_rows`.

## Definition of Done

- Valid `POST /api/legal-holds` с `scope_type=query_scope` создаёт pending hold.
- Invalid selector возвращает 400 и не создаёт hold.
- `legal_holds` хранит normalized selector JSON, SHA256 hash и version=1.
- Preview/create эквивалентные selectors дают одинаковый `selector_hash`.
- `legal_hold_events` новые rows пишутся с `canonical_version='v2'` и scope fields.
- Verifier поддерживает legacy v1 и v2 rows.
- Tampered `scope_query_hash` ломает v2 chain verification.
- whole_user/date_range behavior не изменён.
- Tenant admin не может создать query_scope hold для другого org.

## Проверка

- `go test -tags enterprise ./internal/legalhold ./internal/chain -count=1`
- `go test -tags enterprise ./... -count=1`
- `go test ./... -count=1`
- `git diff --check`

## Риски / зависимости

- Purge enforcement для `query_scope` остаётся out of scope; hold создаётся и
  проходит workflow, но scoped purge semantics будет отдельной задачей.
- Verifier требует migration 024 для чтения v2 fields из `legal_hold_events`.
- Старые rows без v2 fields должны оставаться проверяемыми как `v1`.

## Roadmap

### v1

- Query-scope create.
- WORM canonical v2 для legal hold events.
- Backward-compatible verifier.

### v2+

- Query-scoped purge protection.
- Selector manifest в evidence bundle.
- Optional BYOK encryption для selector JSON.

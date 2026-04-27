# bd-ShadowAI-ah4 — PR-L8.1a query_scope selector foundation

## Контекст

PR-L8 RFC зафиксировал безопасный `query_scope` selector для legal hold:
оператор передаёт JSON DSL, а продукт добавляет tenant/user boundary
самостоятельно. До L8.1a `query_scope` существовал как доменная константа,
но create path намеренно возвращал `unsupported_scope_type`.

CASS-поиск по `L8.1 query_scope selector foundation legal hold`,
`legalhold query_scope selector preview endpoint` и
`PR-L8 RFC legal hold query_scope JSON DSL` не нашёл прошлых session-логов.
Фактическим источником стали локальный код и RFC.

## Цель

Добавить foundation-слой без включения enforcement:

- selector parser/validator/normalizer/hash/compiler;
- preview endpoint `POST /api/legal-holds/preview`;
- DB schema seed для будущего storage;
- сохранить fail-closed create path для `query_scope`.

## Scope In

- `backend/internal/legalholdselector` — JSON DSL v1.
- `legalhold.Service.PreviewQueryScopeInOrg`.
- `PGRepository.PreviewQueryScope` через параметризованный SQL.
- Handler `Preview` и enterprise route wiring.
- Enterprise migration `023_legal_hold_query_scope_preview.sql`.
- Unit/handler tests.

## Scope Out

- Создание `query_scope` hold.
- Purge enforcement.
- WORM `CanonicalLegalHoldEventV2`.
- Evidence bundle selector manifest.
- UI selector builder.
- `conversation_id` audit column.

## План реализации

1. Добавить selector package с тестами parser/normalizer/compiler.
2. Добавить preview stats интерфейс в legalhold service.
3. Реализовать PG preview поверх `audit_logs` с implicit `org_id` + `user_id`.
4. Добавить handler response и admin audit metadata без raw selector.
5. Добавить enterprise migration для будущих columns/constraints.
6. Прогнать targeted и enterprise regression.

## Размышления

Рассмотрены варианты: сразу включить создание `query_scope` hold или
ограничиться preview foundation. Принято решение оставить создание
отключённым, потому что без WORM canonical v2 и purge integration storage
сам по себе менял бы юридическую семантику hold.

Альтернатива с частичным purge fallback отклонена: RFC явно требует
fail-closed, так как broadening/narrowing legal preservation хуже
пропущенного purge tick.

Selector сделан strict: корневой `v:1` обязателен, неизвестные ключи
отклоняются, `org_id`/`user_id` запрещены как operator-authored fields.

## Definition of Done

- Selector package отклоняет invalid field/operator/value/depth/list/key.
- Эквивалентные selectors дают одинаковый normalized JSON/hash.
- SQL compiler не интерполирует raw values.
- Preview возвращает `selector_hash`, `matched_rows`, timestamps и explanation.
- Preview не создаёт hold.
- Create `scope_type=query_scope` остаётся 400.
- Migration idempotent через `IF NOT EXISTS`.
- Regression tests зелёные.

## Проверка

- `go test ./internal/legalholdselector -count=1`
- `go test -tags enterprise ./internal/legalhold ./internal/legalholdselector -count=1`
- planned final: `go test -tags enterprise ./... -count=1`

## Риски / зависимости

- `query_scope` columns пока не используются create path; это intentional
  foundation для L8.1b.
- Tenant preview зависит от корректного target user org lookup.
- Migration допускает `query_scope` shape в DB, но application path всё ещё
  блокирует создание до enforcement PR.

## Roadmap

### v1

- Selector foundation + preview only.
- Fail-closed create path preserved.

### v2+

- Store normalized selector on create.
- Add legal_hold_events canonical v2.
- Compile query-scoped purge protection.
- Add selector manifest to evidence bundles.

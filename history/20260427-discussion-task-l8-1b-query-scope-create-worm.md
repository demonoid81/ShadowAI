# Задача — PR-L8.1b query_scope create + WORM canonical v2

## КОНТЕКСТ

Legal hold track после L8.1a.

L8.1a уже добавил foundation:

- `backend/internal/legalholdselector`;
- `POST /api/legal-holds/preview`;
- selector hash / explanation / parameterized SQL compiler;
- migration seed для `legal_holds.scope_query_*`;
- create path для `scope_type=query_scope` сохранён fail-closed.

Источник: `history/20260427-bd-ShadowAI-ah4-l8-1a-query-scope-foundation.md`.

RFC PR-L8 фиксирует, что selector details не должны жить только в
`metadata_json`, потому что current `legal_hold_events` canonical form
не покрывает metadata.

Источник: `docs/rfcs/2026-04-pr-l8-legal-hold-query-scope-rfc.md`.

## ТЕКУЩЕЕ СОСТОЯНИЕ

Сейчас оператор может выполнить preview query-scoped hold:

- selector валидируется;
- возвращается `selector_hash`;
- считаются matched rows;
- hold не создаётся.

Но:

- `POST /api/legal-holds` с `scope_type=query_scope` возвращает `400`;
- `legal_hold_events` не хранит `scope_query_hash` как first-class column;
- verifier не умеет `CanonicalLegalHoldEventV2`;
- purge enforcement для query scope ещё не должен включаться.

## ЗАДАЧА

Реализовать **PR-L8.1b: Legal hold `query_scope` create + WORM canonical v2**.

Цель: разрешить создание `query_scope` hold только для валидного selector’а
и сделать selector hash tamper-evident через chained `legal_hold_events`
canonical v2.

## ТРЕБОВАНИЯ

- Create path использует тот же `legalholdselector.Compile`, что и preview.
- Create сохраняет normalized selector JSON в `legal_holds.scope_query_json`.
- Create сохраняет `scope_query_hash` и `scope_query_version=1`.
- Preview hash и create hash для эквивалентных selectors совпадают.
- `whole_user` и `date_range` behavior не меняется.
- `query_scope` hold создаётся в `pending`, как остальные legal holds.
- DSAR semantics остаётся whole-user blocking после approve/release_pending.
- Purge selective enforcement не входит в эту задачу.
- `legal_hold_events` получает first-class поля:
  - `scope_type`;
  - `scope_query_hash`;
  - `scope_query_version`;
  - `scope_date_from`;
  - `scope_date_to`;
  - `canonical_version`.
- Добавить `CanonicalLegalHoldEventV2`.
- Verifier поддерживает legacy v1 и new v2 rows.
- Admin audit metadata содержит `selector_hash`, `matched_rows`,
  `scope_type=query_scope`, но не raw prompt/response body.

## КРИТЕРИИ ГОТОВНОСТИ (Definition of Done)

- `POST /api/legal-holds` с валидным `scope_type=query_scope` создаёт
  pending hold.
- Invalid selector возвращает `400` и не создаёт hold/event.
- `legal_holds.scope_query_json` хранит normalized JSON, а не raw request.
- `legal_holds.scope_query_hash` равен SHA256(normalized JSON).
- `legal_hold_events` create row получает `canonical_version='v2'` и
  selector/scope fields.
- Legal hold event verifier:
  - верифицирует legacy v1 rows;
  - верифицирует v2 rows;
  - ловит tampering `scope_query_hash`.
- Existing `whole_user` и `date_range` tests проходят без изменения
  поведения.
- Preview/create hash equivalence покрыта regression test.
- Tenant admin не может создать `query_scope` hold для пользователя
  другого org.
- `go test -tags enterprise ./internal/legalhold ./internal/chain -count=1`
  проходит.
- `go test -tags enterprise ./... -count=1` проходит.
- `go test ./... -count=1` проходит.
- `git diff --check` проходит.

## ДОПОЛНИТЕЛЬНО

Анти-фантазия / edge cases:

- Не включать purge enforcement в L8.1b.
- Не делать fallback `query_scope -> whole_user`.
- Не хранить raw selector только в admin event metadata.
- Не включать raw prompt/response body в selector или audit metadata.
- Не разрешать selector fields `org_id` / `user_id`.
- Не ломать verifier для старых `legal_hold_events` без new columns.
- Не делать SQL string interpolation из selector values.
- Не расширять selector DSL за пределы L8 RFC v1 allowlist.

## Размышления

Рассмотрены варианты: включить create + WORM canonical, сразу включить
purge enforcement, либо переключиться на другой roadmap-трек.

Принято решение: сначала create + WORM canonical v2. Это закрывает
tamper-evidence gap перед destructive retention behavior.

Альтернатива purge-first отклонена: если selector можно переписать после
создания hold без WORM-detectability, purge будет исполнять изменённый
selector.

Альтернатива другого roadmap-трека отклонена как immediate next:
L8.1a оставил legal hold query scope в промежуточном preview-only
состоянии.

## Возможные следующие шаги

1. По команде `реализуй` создать bd-задачу для L8.1b.
2. Через ast-index проверить symbols/callers:
   `CanonicalLegalHoldEvent`, `VerifyLegalHoldEvents`,
   `insertHoldEvent`, `CreateScopedHoldInOrg`, `scanHoldFull`,
   `scanHolds`.
3. Выполнить TDD:
   - verifier/canonical tests;
   - create handler tests;
   - repository/service persistence tests;
   - regression для legacy whole_user/date_range.

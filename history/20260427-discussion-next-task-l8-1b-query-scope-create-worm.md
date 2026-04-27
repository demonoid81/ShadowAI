# Обсуждение следующей задачи — L8.1b query_scope create + WORM canonical

## Тема / вопрос

Определить следующую задачу после `PR-L8.1a: query_scope selector
foundation`.

## Контекст

Использованные источники:

- `history/20260427-bd-ShadowAI-ah4-l8-1a-query-scope-foundation.md`
  фиксирует, что L8.1a реализовал selector foundation + preview only, а
  create path для `query_scope` сохранён fail-closed.
- `docs/rfcs/2026-04-pr-l8-legal-hold-query-scope-rfc.md` фиксирует
  L8.1 phases: schema, selector package, service/API, purge, evidence
  export. В D7 указано, что selector details не должны жить только в
  metadata, потому что `metadata_json` не входит в текущий WORM canonical.
- CASS search `L8.1b query_scope WORM create legal hold` вернул 0 hits,
  поэтому локальный RFC и history являются источником истины.

## Размышления

Рассмотрены варианты:

1. Сразу перейти к purge enforcement.
2. Сначала включить `query_scope` create и WORM canonical v2.
3. Отложить L8 и перейти к другому roadmap-треку.

Принято решение рекомендовать вариант 2: **PR-L8.1b — query_scope create
+ WORM canonical v2**.

Альтернатива сразу делать purge enforcement отклонена: без chained
selector hash в `legal_hold_events` DBA может изменить selector после
создания hold, а purge будет исполнять уже изменённое значение. Это
нарушает WORM/evidence invariant.

Альтернатива сменить трек отклонена как immediate next: L8.1a уже
создал foundation, и незакрытый create/WORM слой является ближайшим
логическим continuation.

## Рекомендованная задача

**PR-L8.1b: Legal hold `query_scope` create + WORM canonical v2**

### Контекст

`query_scope` preview уже умеет валидировать selector, считать
stable hash, explain и preview count. Но `POST /api/legal-holds` всё ещё
возвращает `400 unsupported_scope_type`, а `legal_hold_events` не содержит
first-class selector fields в WORM canonical.

### Задача

Разрешить создание `query_scope` hold только для валидного selector’а и
сделать selector hash tamper-evident через chained `legal_hold_events`
canonical v2.

### Требования

- Create пересчитывает selector тем же `legalholdselector` package, что и preview.
- Create сохраняет normalized selector JSON, selector hash и version в `legal_holds`.
- Preview hash и create hash для эквивалентных selectors совпадают.
- `legal_hold_events` получает first-class columns:
  `scope_type`, `scope_query_hash`, `scope_query_version`,
  `scope_date_from`, `scope_date_to`, `canonical_version`.
- `CanonicalLegalHoldEventV2` включает selector/scope fields.
- Legacy v1 legal hold event rows продолжают верифицироваться.
- Purge enforcement всё ещё out of scope для L8.1b.

### Definition of Done

- `POST /api/legal-holds` с валидным `scope_type=query_scope` создаёт pending hold.
- Invalid selector возвращает 400 и не создаёт hold/event.
- `query_scope` hold stores normalized JSON/hash/version.
- `legal_hold_events` create row stores scope/hash/version and `canonical_version='v2'`.
- Verifier dispatches legal_hold_events v1/v2 and catches tampered selector hash.
- Admin event metadata содержит `selector_hash`, `matched_rows`,
  `scope_type=query_scope`, но не raw prompt/response body.
- `date_range` и `whole_user` behavior не меняется.
- Enterprise tests pass.

## Варианты

### Вариант A — L8.1b create + WORM canonical v2

Плюсы: закрывает tamper-evidence gap перед purge, минимально продолжает
уже реализованный foundation, не расширяет destructive behavior.

Минусы: `query_scope` hold будет блокировать DSAR whole-user, но retention
purge ещё не будет selective до L8.1c.

### Вариант B — L8.1c purge enforcement сразу

Плюсы: быстрее получить end-to-end query-scoped retention.

Минусы: опасно до WORM canonical v2; selector rewrite будет плохо
детектироваться.

### Вариант C — другой roadmap трек

Плюсы: можно переключиться на BYOK/ops/security hardening.

Минусы: L8 останется в промежуточном состоянии preview-only.

## Открытые вопросы

- Нужно ли на L8.1b добавлять feature flag для `query_scope` create, или
  достаточно enterprise-only availability?
- Нужно ли create response возвращать `selector_hash` прямо в body, или
  достаточно admin event metadata и subsequent list response в L8.1b?

## Возможные следующие шаги

1. По команде пользователя создать bd-задачу `PR-L8.1b: query_scope create + WORM canonical v2`.
2. Перед реализацией проверить через ast-index: `CanonicalLegalHoldEvent`,
   `VerifyLegalHoldEvents`, `insertHoldEvent`, `CreateScopedHoldInOrg`,
   `scanHoldFull`, `scanHolds`.
3. Реализовать TDD: сначала verifier/canonical tests, затем create handler
   tests, затем repository/service changes.

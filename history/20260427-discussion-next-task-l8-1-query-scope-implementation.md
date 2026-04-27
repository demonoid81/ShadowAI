# Обсуждение следующей задачи — L8.1 query_scope implementation slice

## Тема / вопрос

Определить следующую задачу после PR-L8 RFC.

## Контекст

CASS был проверен, но недоступен как актуальный источник:
`cass health` вернул `index stale`. Поэтому источником истины стали
локальные документы и фактические history/RFC файлы.

Найденные источники:

- `docs/rfcs/2026-04-pr-l8-legal-hold-query-scope-rfc.md` фиксирует
  L8 как design-only и указывает L8.1 implementation breakdown.
- `docs/production-hardening.md` фиксирует: `query_scope` design
  captured in PR-L8 RFC, implementation remains future work.
- `docs/compliance/soc2-iso-control-mapping.md` фиксирует:
  query-scope implementation remains roadmap.
- `docs/privacy-ops-runbook.md` фиксирует:
  L8 RFC есть, implementation остаётся v2+ roadmap.

## Размышления

Рассмотрены варианты:

- **L8.1 full implementation одним PR**: schema + parser/compiler +
  preview + create + purge + evidence.
- **L8.1a schema + selector package + preview**: реализовать безопасный
  фундамент без изменения purge semantics.
- **BYOK2**: KMS/envelope encryption после BYOK1 RFC.
- **L7.1 external routing**: email/webhook/PagerDuty/ticket creation
  поверх L7 signals.

Принято рекомендованное направление: **L8.1a — query_scope schema,
selector package и preview endpoint**.

Альтернатива full implementation одним PR отклонена как слишком широкая:
purge integration и WORM canonical changes являются destructive /
evidence-sensitive path, их лучше делать после того, как parser,
normalizer и preview покрыты тестами.

BYOK2 отклонён как immediate next task: локальные документы по-прежнему
связывают его с customer/KMS requirement.

L7.1 external routing отклонён: L7 уже создал durable signals, а
конкретная доставка зависит от customer stack.

## Рекомендованная следующая задача

**PR-L8.1a: Legal hold `query_scope` selector foundation**

## КОНТЕКСТ

Legal hold поддерживает `whole_user` и `date_range`. `query_scope`
существует как константа, но API возвращает 400. L8 RFC зафиксировал
JSON DSL, allowlist полей, canonical hash, preview/explain contract и
fail-closed semantics.

## ТЕКУЩЕЕ СОСТОЯНИЕ

- RFC готов.
- `query_scope` creation intentionally unsupported.
- DB constraints пока разрешают только `whole_user|date_range`.
- Purge защищает только `whole_user` и `date_range`.
- DSAR блокирует весь user для любого active/release_pending hold.

## ЗАДАЧА

Реализовать foundation для `query_scope` без включения purge
enforcement:

1. migration для `legal_holds.scope_query_json`,
   `scope_query_hash`, `scope_query_version`;
2. новый package `backend/internal/legalholdselector`;
3. JSON DSL parse/validate/normalize/hash/explain;
4. `POST /api/legal-holds/preview` для preview count/explanation;
5. create path всё ещё может оставаться fail-closed для `query_scope`
   до L8.1b, либо включить create в disabled state только если preview
   полностью стабилен.

Рекомендация: **не включать purge integration в L8.1a**.

## ТРЕБОВАНИЯ

- JSON DSL only; no SQL/text DSL.
- Поля v1 только из RFC allowlist:
  `id`, `created_at`, `provider`, `model`, `endpoint`,
  `policy_action`, `outcome`, `pii_detected`.
- `org_id`, `user_id`, raw bodies, metadata запрещены.
- Все SQL predicates только parameterized.
- Canonical hash должен быть stable для equivalent selectors.
- Preview использует тот же compiler, что будущий purge.
- Нет PII в metric labels/admin metadata.
- Tenant admin preview работает только для своего org/user.

## КРИТЕРИИ ГОТОВНОСТИ

- `legalholdselector` покрыт unit-тестами:
  valid selectors, invalid fields, invalid operators, normalization,
  max depth/list limits, stable hash.
- Migration проходит idempotently.
- Preview endpoint возвращает:
  `selector_hash`, `matched_rows`, `oldest_created_at`,
  `newest_created_at`, `explanation`.
- Preview не создаёт hold и не меняет purge behavior.
- `query_scope` create либо остаётся 400, либо явно gated feature flag.
- `git diff --check`, targeted tests и enterprise tests проходят.

## ДОПОЛНИТЕЛЬНО

Anti-fantasy / edge cases:

- Не реализовывать arbitrary SQL.
- Не матчить `request_body` / `response_body`.
- Не добавлять `conversation_id`, пока нет first-class audit column.
- Не делать silent fallback `query_scope -> whole_user`.
- Не включать purge enforcement без отдельного L8.1b review.

## Возможные следующие шаги

1. По команде пользователя создать bd-задачу `PR-L8.1a:
   query_scope selector foundation`.
2. Начать с red tests для normalizer/compiler.
3. Затем migration + package + preview endpoint.

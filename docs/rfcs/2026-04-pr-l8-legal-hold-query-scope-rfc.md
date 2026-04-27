# PR-L8 RFC — Legal Hold `query_scope` Selector Language

**Статус:** design locked для review
**Дата:** 2026-04-27
**Scope:** только RFC; parser/compiler implementation не входит в PR-L8

## 1. Summary

ShadowAI legal hold сейчас поддерживает:

- `whole_user` — защищаются все audit rows target user'а;
- `date_range` — защищаются audit rows target user'а, где
  `audit_logs.created_at` попадает в диапазон hold'а.

`query_scope` уже существует как доменная константа, но создание такого
hold'а intentionally fail-closed с `unsupported_scope_type`. DB
constraints тоже разрешают только `whole_user` и `date_range`.

PR-L8 фиксирует безопасный selector language и rollout plan для будущей
implementation-задачи L8.1. PR-L8 **не** реализует parser, compiler,
migrations, API handlers или purge integration.

## 2. Problem Statement

Regulated customers иногда должны сохранить точный subset audit trail:

- один incident-related request;
- набор запросов к конкретному provider/model;
- класс policy outcome, например blocked/flagged requests;
- узкое временное окно плюс provider/model filters.

`whole_user` для таких случаев сохраняет слишком много unrelated rows.
`date_range` лучше, но всё ещё слишком широк, если у пользователя много
несвязанных запросов в тот же период.

Нужная capability — constrained, explainable и auditable
`query_scope` selector. Он не должен стать arbitrary SQL.

## 3. Current Implementation Facts

Проверено по локальному коду:

- `backend/internal/legalhold/types.go` определяет:
  `ScopeWholeUser`, `ScopeDateRange`, `ScopeQuery`.
- `backend/internal/legalhold/service.go` отвергает `ScopeQuery` через
  `ErrUnsupportedScope`.
- `backend/migrations-enterprise/020_legal_hold_release_4eyes_scope.sql`
  создаёт `scope_type` с check constraint для `whole_user|date_range`.
- `backend/migrations-enterprise/022_legal_hold_scope_constraints.sql`
  enforce'ит корректный shape для `whole_user` и `date_range`.
- `backend/internal/audit/retention_hold.go` защищает rows только для
  `whole_user` или `date_range`.
- `HasActiveHold` блокирует DSAR для `active` и `release_pending`
  holds без интерпретации scope.
- `legal_hold_events` WORM canonical сейчас содержит identity поля
  события, но не scope details.

## 4. Design Goals

1. **No arbitrary SQL.** Operator не передаёт SQL fragments.
2. **Tenant safe by construction.** Selector не может override'ить
   `org_id` или `target_user_id`.
3. **Explainable.** Каждый selector можно отрендерить как стабильное
   human-readable объяснение для legal/compliance review.
4. **Audit-evident.** Selector hash включается в chained evidence.
5. **Fail closed.** Invalid/unknown/un-compilable selectors блокируют
   создание hold'а или purge tick.
6. **Bounded v1.** Стартуем только с полей, которые уже являются
   first-class columns в `audit_logs`.

## 5. Non-Goals

- Full SQL или CEL/Rego policy language.
- Filtering по raw prompt/response body.
- Filtering по arbitrary JSON metadata.
- Применение query scope к `admin_event_logs` в v1.
- Cross-user или cross-tenant holds.
- UI selector builder.
- External legal CMS integration.

## 6. Threat Model

| Threat | Risk | Required Control |
|--------|------|------------------|
| SQL injection | Operator-provided selector меняет purge SQL | JSON DSL компилируется только через field/operator allowlist и bound parameters |
| Tenant bypass | Selector включает другой `org_id` или user | `org_id` и `target_user_id` являются implicit constraints, не selector fields |
| Over-broad selector | Legal hold сохраняет слишком много данных | Preview count + explanation до approval; admin events фиксируют count/hash |
| Under-broad selector | Relevant evidence purge'ится | Fail-closed validation; bounded operators; approval recomputes preview |
| DBA selector rewrite | DB row меняется после approval | Selector hash хранится в chained `legal_hold_events` canonical v2 |
| Purge/preview mismatch | Preview показывает protection, purge удаляет | Preview и purge используют один compiler package |
| Ambiguous audit trail | Auditor не может объяснить hold | Хранятся normalized selector, selector hash, preview count и explanation |
| Resource exhaustion | Огромный `in` list или deep boolean tree | Лимиты depth/list/predicate/parameter count |

## 7. Decision Log

### D1 — JSON DSL, не text DSL

`query_scope` использует versioned JSON DSL.

Accepted shape:

```json
{
  "v": 1,
  "all": [
    {"field": "created_at", "op": "between", "value": ["2026-04-01T00:00:00Z", "2026-04-30T23:59:59Z"]},
    {"field": "provider", "op": "in", "value": ["openai", "anthropic"]},
    {"field": "policy_action", "op": "eq", "value": "blocked"}
  ]
}
```

Rationale: JSON не требует SQL-like parser, поддерживает
детерминированную canonicalization и валидируется обычными Go structs.

Rejected:

- SQL `WHERE` string — injection и review risk.
- Free-form CEL/Rego — слишком широкая модель для L8.1 и хуже
  объясняется non-engineering auditor'у.

### D2 — Tenant/user boundary implicit

Selector не может включать `org_id` или `user_id`.

Каждый compiled predicate оборачивается:

```sql
audit_logs.org_id = $orgID
AND audit_logs.user_id = $targetUserID
AND (<compiled selector>)
```

Rationale: tenant/user boundary должен enforce'иться продуктом, а не
operator-authored selector content.

### D3 — v1 field allowlist

Allowed v1 fields:

| Field | Source | Operators | Notes |
|-------|--------|-----------|-------|
| `id` | `audit_logs.id` | `eq`, `in` | Per-query hold через explicit audit row IDs |
| `created_at` | `audit_logs.created_at` | `between`, `gte`, `lte` | UTC RFC3339 only |
| `provider` | `audit_logs.provider` | `eq`, `in` | Exact string match |
| `model` | `audit_logs.model` | `eq`, `in` | Exact string match |
| `endpoint` | `audit_logs.endpoint` | `eq`, `in` | Exact string match |
| `policy_action` | `audit_logs.policy_action` | `eq`, `in` | Security verdict only |
| `outcome` | `audit_logs.outcome` | `eq`, `in`, `is_empty` | Streaming transport outcome |
| `pii_detected` | `audit_logs.pii_detected` | `eq` | Boolean |

Explicitly not in v1:

- `conversation_id` — сегодня это не first-class `audit_logs` column.
- `request_body` / `response_body` — могут содержать PII и зависят от
  payload mode.
- JSON metadata fields — недостаточно canonical для legal hold
  enforcement.
- token/cost ranges — полезно для analytics, но не для v1 legal
  preservation.

### D4 — Boolean form bounded

Supported boolean nodes:

- `all`: conjunction;
- `any`: disjunction.

Limits:

- max depth: `3`;
- max total predicates: `20`;
- max `in` list length: `100`;
- no `not` in v1.

Rationale: bounded boolean form достаточен для legal preservation и
сохраняет SQL generation predictable.

### D5 — Normalized selector canonical form

L8.1 должен нормализовать selector перед storage/hash:

- object keys sorted;
- string values trimmed;
- `in` values sorted and deduplicated;
- timestamps converted to UTC RFC3339Nano;
- empty boolean groups rejected;
- equivalent selectors produce the same `selector_hash`.

Hash:

```text
selector_hash = hex(SHA256(normalized_selector_json))
```

### D6 — Persistence model

L8.1 migration добавляет в `legal_holds`:

- `scope_query_json JSONB`;
- `scope_query_hash CHAR(64)`;
- `scope_query_version SMALLINT NOT NULL DEFAULT 1`.

Scope check constraint обновляется:

- `whole_user`: no date range, no query JSON/hash;
- `date_range`: date range required, no query JSON/hash;
- `query_scope`: query JSON/hash required, no date range.

Existing `target_user_id` остаётся required. `query_scope` — subset
selector для одного target user, не cross-user search.

### D7 — WORM/evidence model

`metadata_json` не входит в current `legal_hold_events` canonical form,
поэтому selector details не должны жить только в metadata.

L8.1 должен добавить first-class columns в `legal_hold_events`:

- `scope_type`;
- `scope_query_hash`;
- `scope_query_version`;
- optionally `scope_date_from` / `scope_date_to` для consistency.

Добавляется `CanonicalLegalHoldEventV2`:

```text
v2|id|hold_id|action|new_status|actor_id|created_at|scope_type|scope_query_hash|scope_query_version|scope_date_from|scope_date_to|org_id
```

Rationale: auditor может detect'ить selector tampering, сравнив current
`legal_holds.scope_query_hash` с chained create event.

### D8 — Preview and explanation

L8.1 добавляет preview path:

```http
POST /api/legal-holds/preview
```

Request использует те же scope fields, что и create. Response:

```json
{
  "scope_type": "query_scope",
  "selector_hash": "sha256...",
  "matched_rows": 17,
  "oldest_created_at": "2026-04-01T10:00:00Z",
  "newest_created_at": "2026-04-04T11:00:00Z",
  "explanation": "target user rows where provider in [openai,anthropic] and policy_action = blocked"
}
```

Create и approval пересчитывают preview count и пишут его в admin
events. Preview не является authorization; это safety/reviewability
signal.

### D9 — Purge integration fail-closed

Retention-aware purge должен compile'ить каждый active/release-pending
`query_scope` selector. Если любой selector invalid или compiler падает,
purge tick aborts и пишет admin event.

Fallback в `whole_user` или `date_range` запрещён.

Rationale: fallback меняет legal meaning. Silent broadening/narrowing
хуже, чем пропущенный purge tick.

### D10 — DSAR remains whole-user blocked

Для DSAR erasure любой `active` или `release_pending` hold продолжает
блокировать весь user.

Rationale: DSAR erasure destructive на user level. Query-scoped hold
означает, что часть user evidence legally preserved; partial DSAR
erasure требует отдельного selective-scrub design.

### D11 — Evidence bundle impact

Tenant/global evidence bundle после L8.1 должен включать query-scope
selector manifest lines:

```json
{"hold_id":"...","scope_type":"query_scope","selector_hash":"...","selector_json":{...}}
```

Этот файл должен быть hashed в `bundle_manifest.json`. Если customer
не хочет раскрывать selector details, можно добавить hash-only export
flag, но default compliance bundle должен включать selector JSON для
auditor explainability.

## 8. Rejected Alternatives

### A. Store raw SQL selector

Отклонено. Даже с parameter substitution operator-authored SQL делает
tenant isolation и audit explanation хрупкими.

### B. Reuse `request_body` / `response_body` matching

Отклонено для v1. Payload storage mode может быть `none`, `metadata`,
`redacted` или `full`; matching raw bodies будет inconsistent и
PII-sensitive.

### C. Let selector include `org_id`

Отклонено. Tenant scope должен идти из authenticated context и target
user lookup, не из selector content.

### D. Treat unsupported selector as `whole_user`

Отклонено. Это скрывает operator errors и создаёт unreviewable
over-preservation.

### E. Implement per-conversation in v1

Отклонено до появления `conversation_id` как first-class audit column.
Сейчас conversation ID существует в runtime metadata для firewall
context, не как stable audit column.

## 9. L8.1 Implementation Breakdown

### Phase 1 — Schema

- Добавить `scope_query_json`, `scope_query_hash`,
  `scope_query_version` в `legal_holds`.
- Расширить legal hold scope constraints для `query_scope`.
- Добавить scope/hash columns в `legal_hold_events`.
- Добавить `canonical_version` handling для
  `CanonicalLegalHoldEventV2`.

### Phase 2 — Selector Package

Новый пакет:

```text
backend/internal/legalholdselector
```

Responsibilities:

- parse JSON DSL в typed AST;
- validate field/operator/value constraints;
- normalize and hash;
- compile to parameterized SQL predicate;
- render human explanation.

### Phase 3 — Service/API

- Добавить `query_scope` request fields в create/preview.
- Добавить `POST /api/legal-holds/preview`.
- Create сохраняет normalized selector JSON и hash.
- Admin events включают `selector_hash`, `matched_rows`,
  `scope_type=query_scope`; raw prompt/response body не пишется.

### Phase 4 — Purge

- Обновить `PurgeOlderThanRespectingHoldsAndRecordRun`.
- Active/release-pending `query_scope` holds compile'ятся в
  `NOT EXISTS` protection.
- Invalid stored selector aborts purge tick и пишет
  `legal_hold_query_scope_compile_failed`.

### Phase 5 — Evidence Export

- Добавить selector manifest в evidence bundles.
- Verify selector hash against chained legal hold event where available.
- Задокументировать hash-only export tradeoff, если такой флаг будет
  добавлен.

### Phase 6 — Tests

- Unit tests для parser/normalizer/compiler.
- Handler tests для preview/create validation.
- PG integration tests для purge protection.
- WORM verifier tests для `CanonicalLegalHoldEventV2`.
- Tenant smoke tests для cross-org selector rejection.

## 10. Acceptance Criteria for L8.1

- `query_scope` creation succeeds only for valid JSON DSL.
- Invalid field/operator/value/depth/list length returns 400.
- Selector cannot reference `org_id`, `user_id`, raw body or metadata.
- Preview and create produce identical `selector_hash` for equivalent
  selectors.
- Purge protects matching rows and deletes non-matching rows for the
  same target user.
- Purge aborts on invalid stored selector.
- DSAR remains blocked for active/release-pending query-scoped holds.
- Selector hash is included in WORM-chained legal hold event.
- Tenant admin cannot create query-scope hold for another org's user.
- Evidence bundle contains selector manifest or hash-only record with
  explicit disclosure.

## 11. Open Questions

Нет blocking questions для L8.1 kickoff. Deferred:

- Добавлять ли `conversation_id` как `audit_logs` column для L8.2.
- Нужен ли UI selector builder.
- Нужен ли legal CMS webhook для auto-create/auto-release.

## 12. Operator Guidance Until L8.1

Operators должны продолжать использовать:

- `whole_user` для broad preservation;
- `date_range` для time-bounded preservation.

`query_scope` requests должны rejected by API до implementation и
review L8.1.

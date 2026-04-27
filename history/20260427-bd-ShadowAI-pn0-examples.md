# bd ShadowAI-pn0 — примеры L8 query_scope legal hold

## Успешный сценарий 1 — explicit audit row hold

Legal team знает конкретные audit row IDs из incident review.

Selector:

```json
{"v":1,"all":[{"field":"id","op":"in","value":["audit-1","audit-2"]}]}
```

Ожидаемое поведение L8.1:

- selector валиден;
- normalized JSON стабилен;
- `selector_hash` пишется в `legal_holds` и chained
  `legal_hold_events`;
- purge защищает только `audit-1` и `audit-2` для target user/org.

## Успешный сценарий 2 — provider/model/policy hold

Legal team хочет сохранить все blocked запросы target user к OpenAI
GPT-4 за период.

Selector:

```json
{
  "v": 1,
  "all": [
    {"field": "created_at", "op": "between", "value": ["2026-04-01T00:00:00Z", "2026-04-30T23:59:59Z"]},
    {"field": "provider", "op": "eq", "value": "openai"},
    {"field": "model", "op": "eq", "value": "gpt-4"},
    {"field": "policy_action", "op": "eq", "value": "blocked"}
  ]
}
```

Ожидаемое поведение L8.1:

- preview возвращает count и explanation;
- create сохраняет selector hash;
- active/release_pending hold защищает matching rows.

## Граничный сценарий 1 — equivalent selector ordering

Два selector-а отличаются только порядком ключей и `in` values.

Ожидаемое поведение L8.1:

- normalizer сортирует keys и `in` values;
- оба selector-а дают одинаковый `selector_hash`;
- auditor видит одну canonical meaning.

## Граничный сценарий 2 — outcome empty

Нужно выбрать non-streaming rows, где `outcome` пустой.

Selector:

```json
{"v":1,"all":[{"field":"outcome","op":"is_empty","value":true}]}
```

Ожидаемое поведение L8.1:

- compiler генерирует `outcome = '' OR outcome IS NULL`;
- selector не требует raw payload.

## Ошибка 1 — попытка tenant bypass

Selector содержит `org_id`.

```json
{"v":1,"all":[{"field":"org_id","op":"eq","value":"other-org"}]}
```

Ожидаемое поведение L8.1:

- validation возвращает 400;
- admin event содержит `error_code=unsupported_selector_field`;
- hold не создаётся.

## Ошибка 2 — raw body matching

Selector пытается искать строку в `request_body`.

Ожидаемое поведение L8.1:

- validation возвращает 400;
- raw prompt/response matching не поддерживается;
- причина: payload mode может быть none/metadata/redacted/full и поле
  может содержать PII.

## Ошибка 3 — invalid stored selector во время purge

DB содержит corrupted `scope_query_json` у active hold.

Ожидаемое поведение L8.1:

- purge tick aborts fail-closed;
- rows не удаляются;
- admin event `legal_hold_query_scope_compile_failed` создаётся;
- operator чинит hold или откатывает migration вручную.

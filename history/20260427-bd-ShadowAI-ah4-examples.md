# bd-ShadowAI-ah4 — примеры L8.1a

## Happy path 1 — provider + policy_action preview

Request:

```json
{
  "target_user_id": "u-target",
  "scope_type": "query_scope",
  "scope_query": {
    "v": 1,
    "all": [
      {"field": "provider", "op": "in", "value": ["openai", "anthropic"]},
      {"field": "policy_action", "op": "eq", "value": "blocked"}
    ]
  }
}
```

Expected:

- HTTP 200;
- response contains stable `selector_hash`;
- preview counts matching `audit_logs` rows for target user and org;
- no legal hold row is created.

## Happy path 2 — created_at window

Selector:

```json
{
  "v": 1,
  "all": [
    {"field": "created_at", "op": "between", "value": ["2026-04-01T00:00:00Z", "2026-04-30T23:59:59Z"]},
    {"field": "outcome", "op": "is_empty"}
  ]
}
```

Expected:

- timestamps normalize to UTC RFC3339Nano;
- SQL uses bound parameters for the two timestamps;
- `outcome is_empty` compiles to `(outcome IS NULL OR outcome = '')`.

## Edge case 1 — equivalent ordering

Selectors with `all` predicates in different order and `in` values in different
order produce the same normalized JSON and `selector_hash`.

## Edge case 2 — tenant boundary field

Selector:

```json
{"v":1,"field":"org_id","op":"eq","value":"org-b"}
```

Expected:

- HTTP 400 from preview;
- admin event metadata has `error_code=invalid_scope_query`;
- no raw selector is written to admin event metadata.

## Failure case — create remains disabled

Request to `POST /api/legal-holds`:

```json
{
  "target_user_id": "u-target",
  "case_ref": "case-query",
  "reason": "query scope",
  "scope_type": "query_scope"
}
```

Expected:

- HTTP 400;
- metadata `error_code=unsupported_scope_type`;
- no hold is stored.

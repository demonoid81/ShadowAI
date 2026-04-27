# bd-ShadowAI-4ue — примеры L8.1b

## Happy path 1 — query_scope create

Request:

```json
{
  "target_user_id": "u-target",
  "case_ref": "case-query",
  "reason": "regulatory preservation",
  "scope_type": "query_scope",
  "scope_query": {
    "v": 1,
    "all": [
      {"field": "policy_action", "op": "eq", "value": "blocked"},
      {"field": "provider", "op": "in", "value": ["openai", "anthropic"]}
    ]
  }
}
```

Expected:

- HTTP 201;
- hold status is `pending`;
- `legal_holds.scope_query_json` stores normalized JSON;
- response contains `selector_hash`;
- admin metadata contains `selector_hash` and `matched_rows`, not raw selector.

## Happy path 2 — WORM v2 event

Creating the same hold writes a `legal_hold_events` row with:

- `canonical_version='v2'`;
- `scope_type='query_scope'`;
- `scope_query_hash=<selector hash>`;
- `scope_query_version=1`.

Expected verifier behavior:

- v2 canonical includes scope fields;
- recomputation with unchanged row passes.

## Edge case 1 — equivalent selector normalization

Two selectors with the same predicates in different order:

```json
{"v":1,"all":[{"field":"provider","op":"in","value":["anthropic","openai"]},{"field":"policy_action","op":"eq","value":"blocked"}]}
```

```json
{"v":1,"all":[{"field":"policy_action","op":"eq","value":"blocked"},{"field":"provider","op":"in","value":["openai","anthropic"]}]}
```

Expected:

- both compile to the same normalized JSON;
- preview and create produce the same `selector_hash`.

## Edge case 2 — legacy rows remain verifiable

Existing `legal_hold_events` rows with `canonical_version='v1'` or without v2
scope fields are verified through `CanonicalLegalHoldEvent`.

Expected:

- verifier does not require scope columns to be non-empty for v1 rows;
- old chains are not invalidated by L8.1b.

## Failure case — tenant boundary selector

Request:

```json
{
  "target_user_id": "u-target",
  "case_ref": "case-query",
  "reason": "invalid",
  "scope_type": "query_scope",
  "scope_query": {"v": 1, "field": "user_id", "op": "eq", "value": "u-other"}
}
```

Expected:

- HTTP 400;
- no hold is created;
- no legal hold event is created;
- admin metadata contains `error_code=invalid_scope_query`.

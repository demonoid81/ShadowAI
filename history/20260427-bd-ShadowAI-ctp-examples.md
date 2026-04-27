# bd-ShadowAI-ctp — примеры L8.1c

## Happy path 1 — active query_scope protects matching rows

Hold selector:

```json
{
  "v": 1,
  "all": [
    {"field": "provider", "op": "eq", "value": "openai"},
    {"field": "policy_action", "op": "eq", "value": "blocked"}
  ]
}
```

Rows:

- `provider=openai`, `policy_action=blocked` — preserved.
- `provider=anthropic`, `policy_action=allowed` — purged if older than cutoff.

## Happy path 2 — release_pending still protects

Workflow:

1. Create `query_scope` hold.
2. Approve hold: `pending -> active`.
3. Request release: `active -> release_pending`.
4. Run purge.

Expected:

- matching rows remain protected;
- non-matching rows remain purge-eligible;
- final release is still required before protection stops.

## Edge case 1 — user_id NULL rows

If query_scope holds exist but an audit row has `user_id IS NULL`, the row stays
eligible for purge. Legal hold selectors target a concrete user; scrubbed rows
without `user_id` cannot be matched to that user.

## Edge case 2 — whole_user/date_range mixed with query_scope

If a user has an active `whole_user` hold, all rows remain protected even if a
query_scope selector would match only a subset. If the hold is `date_range`, rows
inside the range remain protected; query_scope logic does not weaken date-range
protection.

## Failure case — corrupted stored selector

Stored selector is tampered to:

```json
{"v": 1, "field": "user_id", "op": "eq", "value": "other-user"}
```

Expected:

- purge returns an error before DELETE;
- `rows_deleted=0`;
- all old rows remain;
- `admin_event_logs.action=legal_hold_query_scope_compile_failed`;
- metadata contains `selector_hash`, not raw selector JSON.

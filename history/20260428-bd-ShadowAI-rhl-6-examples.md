# bd ShadowAI-rhl.6 — примеры

## Happy path 1 — emergency provider block

Replica B cached org A policy allowing `openai/gpt-4`. Admin updates policy on
replica A to remove that model. Replica A publishes Redis invalidation for org A.

Ожидаемый outcome: replica B drops org A cache and next request reloads DB,
returning deny before upstream call.

## Happy path 2 — unrelated tenant remains cached

Admin updates org A governance policy. Org B has a cached policy on the same
replica.

Ожидаемый outcome: only org A cache entry is invalidated; org B remains cached.

## Edge case 1 — Redis publish fails

PostgreSQL Upsert succeeds, but Redis publish returns error.

Ожидаемый outcome: local replica has write-through policy; metric
`shadowai_governance_cache_invalidation_publish_errors_total` increments and
operators treat remote replicas as TTL-fallback until verified.

## Edge case 2 — malformed pub/sub message

Redis channel receives invalid JSON or empty `org_id`.

Ожидаемый outcome: message is logged/ignored; no global cache flush happens.

## Failure case — Redis unavailable during incident

Redis is down during emergency block.

Ожидаемый outcome: policy persists in DB and same-replica cache updates, but
other replicas may serve old snapshot until TTL fallback or pod restart. Operator
must restart pods or route traffic to verified replica for immediate containment.

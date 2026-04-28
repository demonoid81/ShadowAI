# bd ShadowAI-rhl.6 — G2.3 distributed governance invalidation

## Тема

Закрыть multi-replica governance cache lag для emergency provider/model block.

## Контекст

`bd ready` показал `ShadowAI-rhl.6` как следующий открытый gap. `cass health`
вернул stale index, поэтому CASS не использовался как источник прошлого
контекста. Локальные источники:

- `backend/internal/governance/cache.go` — per-org in-process cache с TTL 60s.
- `backend/cmd/shadowai/enterprise_wire.go` — enterprise wiring governance
  repository/service.
- `docs/production-hardening.md` — known limit: policy propagation до 60s.

## Размышления

Рассмотрены варианты:

- Отключить cache для emergency path. Альтернатива отклонена: ломает G2.2
  hot-path goal и повышает DB load для каждого Evaluate.
- Делать DB version polling перед каждым request. Альтернатива отклонена:
  возвращает DB read на hot path и усложняет fail-closed semantics.
- Использовать Redis pub/sub invalidation. Принято решение: Redis уже
  production dependency и readiness check. Upsert publishes org-scoped event;
  other replicas drop only that org cache entry. TTL остаётся fallback.

## Scope

### In

- Org-scoped cache invalidation API.
- Redis pub/sub invalidation bus.
- Upsert publish hook.
- Start subscriber in enterprise scheduler lifecycle.
- Tests for remote replica invalidation and publish error visibility.
- Docs/runbook update.

### Out

- Replacing governance evaluator.
- Global cache flush on every policy change.
- Removing TTL fallback.

## План реализации

1. Добавить red tests в `cache_test.go`.
2. Добавить `Invalidate(orgID)` и invalidation metrics.
3. Добавить `InvalidationPublisher` option для `CachingRepository`.
4. Добавить Redis-backed invalidation bus.
5. Передать Redis client в enterprise deps и запустить subscriber.
6. Обновить production docs/runbook.
7. Прогнать enterprise governance tests и regression.

## Definition of Done

- Emergency policy update виден на другой cache instance без ожидания TTL.
- Invalidation scoped by `org_id`.
- Publish failure не silent: есть metric/log.
- Same-replica write-through остаётся.
- Hot path cache hit не делает DB query.
- Docs больше не утверждают TTL-only propagation.

## Проверка

- `go test -tags enterprise ./internal/governance -count=1`
- `go test -tags enterprise ./... -count=1`
- `git diff --check`
- `git diff --cached --check`
- `ast-index update`

## Риски / зависимости

- Redis pub/sub delivery is best-effort. TTL remains fallback if Redis is down.
- In-flight requests are not interrupted; policy applies to new requests.
- Publish failure after DB commit is visible via metric/log, but cannot roll back
  the already persisted policy update.

## Roadmap

### v1

Redis pub/sub org-scoped invalidation.

### v2+

- Prometheus alert for invalidation publish errors.
- Optional admin endpoint to force org cache invalidation across replicas.
- Optional governance policy export/report diff against vendor-risk register.

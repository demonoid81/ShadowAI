# PR-T2.1 — Schema Seed

**Date:** 2026-04-25  
**Status:** Completed  
**Migration files:**
- `backend/migrations/018_tenant_schema_seed.sql` (core)
- `backend/migrations-enterprise/018_tenant_schema_seed_enterprise.sql` (enterprise)

---

## Цель

Первый implementation PR tenant isolation. Только миграции, zero runtime behavior change.

---

## Решения и обоснования

### organizations table

Стабильный UUID `00000000-0000-0000-0000-000000000001` для default org.
ON CONFLICT DO NOTHING — идемпотентность.

### ADD COLUMN NOT NULL DEFAULT

В PG 11+ ADD COLUMN с константным DEFAULT — instant metadata operation,
таблица не переписывается. Все существующие строки получают default
через catalog lookup без физического backfill.

### Что не получило org_id

- `budgets`: изоляция через `budgets.user_id → users.org_id` JOIN (RFC D6.2).
  Добавление отдельной колонки избыточно для T2.
- `audit_chain_anchors`: глобальная таблица по RFC D4, нет tenant scope.

### admin_event_logs: source_org_id / target_org_id

First-class nullable UUID columns без FK на organizations.
Причина отсутствия FK: actor может быть global_admin (org=""),
target может не существовать в org table в edge cases.
В canonical v2 оба поля включаются как пустая строка при NULL.

### provider_governance_policies singleton constraint

Existing index `idx_gov_policy_singleton_active` (WHERE is_active=true) сохранён.
Unique-per-org enforcement → отдельный PR Phase 4. Иначе T2.1 сломал бы
текущий single-policy semantics без замены runtime code.

### scim_tokens

New table. `token_hash VARCHAR(128) UNIQUE NOT NULL` — хранит hash токена,
никогда plaintext. `is_active` позволяет soft revoke с сохранением audit trail.

### CHECK constraints

Добавлены через DO $$ block pattern — idempotent в любом порядке применения.
Значения: `canonical_version IN ('v1','v2')`, `scope IN ('org','global')`.

---

## Что НЕ менялось

- Handlers: никаких изменений route behavior.
- Repositories: никаких новых orgID параметров.
- Services: никаких изменений бизнес-логики.
- Canonical write paths: `canonical_version` колонка добавлена, но runtime
  по-прежнему пишет v1 canonical. v2 write path → Phase 3 (repository filters).

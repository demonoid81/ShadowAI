# PR-T1 Tenant Isolation RFC — Session Notes

**Дата:** 2026-04-25  
**Статус:** Draft RFC создан, ожидает sign-off

## Тема
RFC для tenant/org isolation model перед PR-T2 implementation.

## Контекст
После E1/O1/E2/O3 (identity, SCIM, ops, CI/smoke) следующий стратегический шаг — зафиксировать tenant boundary model. Без этого опасно добавлять tenant_id в audit, legal hold, governance.

## Принятые решения

### D1: Always-on default tenant (Вариант A)
- Принято: единый код path, проще тестировать, меньше isolation bugs
- Отклонено: enterprise-only flag (MULTI_TENANT=true) — создаёт divergent paths
- Default org UUID: `00000000-0000-0000-0000-000000000001`

### D2: Роли
- `tenant_admin` — текущий `admin`, только свой org
- `global_admin` — всё, с обязательным audit marker (source_tenant + target_tenant)
- `support_admin` — деферирован до PR-T3
- Break-glass — явно global, JWT: org_id=null, scope=global

### D3: WORM chain под tenant filter
- Отклонено: per-tenant chain (слишком сложно для существующей infrastructure)
- Принято: global chain + tenant-annotated rows
- Per-tenant bundle проверяет integrity tenant subset
- Global chain continuity — отдельная operator-level ответственность

### D4: Zero-downtime migration
- `org_id UUID NOT NULL DEFAULT '...'` — DEFAULT value, не backfill query
- Новые rows: получают org_id при insert
- Существующие rows: получают DEFAULT при ALTER TABLE

## Открытые вопросы (OQ-1 .. OQ-5)
OQ-1: per-tenant bundle README disclaimer  
OQ-2: SCIM — один endpoint или X-Org-ID header  
OQ-3: Budget — per-user или per-org aggregate  
OQ-4: audit-verify global flag semantics  
OQ-5: internal_db_sources — org-scoped или global  

**Реализация не начинается до закрытия OQ-1..5.**

## Deliverables созданы
- `docs/rfcs/2026-04-pr-t1-tenant-isolation.md` — полный RFC
- Таблица affected tables с tenant strategy
- Таблица affected handlers
- Decision log с rationale
- PR-T2 implementation breakdown (6 phases)
- Acceptance criteria

## Следующие шаги
1. Закрыть OQ-1..5 (ownership указан в RFC §7)
2. Sign-off на RFC
3. Начать PR-T2 Phase 1 (schema + seed migration)

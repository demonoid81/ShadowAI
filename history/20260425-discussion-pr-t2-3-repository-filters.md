# PR-T2.3 Discussion — Tenant Repository Filters

**Date:** 2026-04-25  
**Status:** Discussion — ждёт команды «реализуй»  
**Scope:** RFC T2 Phase 3 — repository filters для всех tenant-scoped слоёв

---

## Контекст

После T2.1 (schema seed) и T2.2 (auth claims + org resolution), `claims.OrgID`
уже доступен в каждом authenticated request. T2.3 делает isolation реальным:
все read/write операции фильтруются по org_id.

---

## Согласованный scope

### In-Scope
1. Auth/users: ListUsers, GetByID, UpdateUser, SCIM/OIDC — tenant-scoped
2. Audit: audit_logs reads/status/dashboard — tenant-scoped
3. Governance: per-org policy, singleton constraint migration
4. Internal DB sources: list/get/update/delete — tenant-scoped
5. SCIM: token → org_id resolution via scim_tokens; email-link scoped

### Non-Scope (deferred)
- Per-tenant WORM bundle subset proofs → T3/W6
- Org management UI/API → отдельный PR
- Cross-org user moves → admin workflow
- Budget org cap → T2.1/G4

---

## Замечания к реализации

### 1. Governance singleton migration
Текущий `idx_gov_policy_singleton_active` (WHERE is_active=true) — global.
Нужна замена на per-org:
```sql
DROP INDEX IF EXISTS idx_gov_policy_singleton_active;
CREATE UNIQUE INDEX idx_gov_policy_active_per_org
    ON provider_governance_policies (org_id)
    WHERE is_active = true;
```
DROP не поддерживает CONCURRENTLY — кратковременный lock на таблицу.
В single-org deploy безопасно (одна строка). Зафиксировать как migration риск.

### 2. CountUsers разделить явно
- `CountUsers(ctx)` — глобальный, только для bootstrap first-user в Register
- `CountUsersByOrg(ctx, orgID)` — для admin dashboard/stats
Смешивание создаст дыру: first-user check в новой org пройдёт неожиданно.

### 3. Proxy → governance wiring
`EvaluateRequest` в governance service должен принять `orgID string`.
Без этого — governance глобальна даже после per-org migration.
Легко пропустить в governance-scope commit без trace до proxy.

### 4. SCIM email-link cross-org
GetByEmail в SCIM lookup должен содержать `AND org_id=$2`.
Без этого: SCIM token org A может залинковать пользователя из org B.
Добавить в acceptance criterion явно.

### 5. Dashboard в audit-scope commit
`/dashboard/stats`, `/usage`, `/top-users` агрегируют из `audit_logs` и `users`.
Включить явно в T2.3-audit-internaldb-scope.

### 6. IsGlobalClaims helper
```go
func IsGlobalClaims(c *Claims) bool {
    return c != nil && (c.BreakGlass || c.Role == RoleGlobalAdmin)
}
```
RequireOrg должен возвращать error только при `!global && orgID == ""`.

---

## Порядок коммитов (согласован)
1. T2.3-auth-scope: helpers + auth/users repo filters
2. T2.3-governance-scope: per-org policy index + service/repo
3. T2.3-audit-internaldb-scope: audit/dashboard/internal-db filters
4. T2.3-scim-scope: scim token org resolution + SCIM repo filters
5. T2.3-smoke-docs: multi-tenant smoke + RFC/runbook note

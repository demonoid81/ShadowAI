# PR-T1: Tenant / Org Isolation RFC

**Status:** Draft — awaiting sign-off before PR-T2 implementation begins  
**Date:** 2026-04-25  
**Author:** Mikhail (assisted by Claude)  
**Supercedes:** None  
**Blocked by:** None  
**Blocks:** PR-T2 (tenant schema backfill + repo filters)

---

## 1. Problem Statement

ShadowAI is currently strictly single-tenant: all users, audit logs, governance policies,
legal holds, budgets, and WORM evidence reside in one undifferentiated namespace.

For a self-hosted single-customer deployment this is acceptable. For SaaS, shared
control-plane, or MSP models it is insufficient: a single admin or API path mistake
can expose or mutate another organization's data. The risk is not hypothetical —
audit chain anchors, legal hold evidence, and governance policy are compliance artifacts
that must be strictly isolated by organization.

This RFC defines the isolation model before any `tenant_id` column is added. The goal
is to prevent a partial multi-tenant system with isolation gaps in audit, governance,
or legal hold.

---

## 2. Decision Log

### D1: Tenant model — always-on vs enterprise-only

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| **A — Always-on (default tenant)** | Every deploy gets a default org. Single-tenant gets `org_id = default`. | Simple test matrix; no conditional logic; cleaner audit/evidence semantics | Slightly more migration work |
| B — Enterprise/SaaS-only flag | `tenant_id` only when `MULTI_TENANT=true` | Minimal change for existing users | Two code paths; easy to forget filter; compliance gap risk |

**Decision: A — Always-on.**

Rationale: Option B creates divergent code paths that are harder to test and
audit. Conditional logic around tenant filtering is the most common source of
isolation bugs. A default tenant makes the current self-host deployment a
degenerate case of the general model, not a special case.

Default tenant: `org_id = "00000000-0000-0000-0000-000000000001"` (stable UUID,
seeded in migration).

---

### D2: Admin model — tenant_admin vs global_admin

| Role | Scope | Cross-tenant access | Audit requirement |
|------|-------|---------------------|-------------------|
| `admin` (existing) | Own tenant | None | Standard admin events |
| `tenant_admin` | Own tenant | None | Standard admin events |
| `global_admin` | All tenants | Read + write any tenant | **Every cross-tenant action logged** with source_tenant + target_tenant |
| `support_admin` (future) | All tenants | Read-only | All reads logged |

**Decision:** Rename current `admin` → `tenant_admin`. Add `global_admin` with
mandatory cross-tenant audit marker. `support_admin` deferred to PR-T3.

Global admin must be explicitly granted; it cannot be auto-provisioned via OIDC
group mapping without `ALLOW_GLOBAL_ADMIN_OIDC_PROVISION=true` (dangerous override,
prod-validated).

Break-glass is **global by default** — it must produce a `break_glass_login_success`
event that includes `effective_tenant=global`. No tenant filter on break-glass JWT.

---

### D3: WORM/evidence chain semantics under tenant filtering

**Rejected:** Per-tenant chain (one HMAC chain per tenant). Too complex to implement;
existing chain infrastructure is table-scoped, not tenant-scoped.

**Accepted:** Global chain with tenant-annotated rows.

- `audit_logs.org_id` is added but the HMAC chain remains global.
- `audit-verify --table all` verifies the global chain (all orgs).
- `audit-export-evidence --org-id <id>` exports a **per-tenant bundle** containing:
  - Only anchors whose seq range includes org rows
  - chain_inventory filtered by org
  - A README note: "This bundle proves integrity of org X's rows within the global chain. Cross-org continuity requires global bundle."
- Evidence export for global admin: `audit-export-evidence` without `--org-id` exports everything.

**Compliance note:** The per-tenant bundle provides evidence that org X's rows were
not modified. It does not prove the global chain was not tampered with (e.g., rows
from other orgs replaced). Global chain verification is a separate, operator-level
responsibility.

---

### D4: Migration strategy for existing single-tenant deployments

1. Add `org_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001'` to all tenant-scoped tables.
2. Migration is additive (no DROP, no breaking NOT NULL without DEFAULT) — safe for rolling restart.
3. Seed migration inserts the default org row into a new `organizations` table.
4. All existing rows automatically belong to the default org via the DEFAULT value.
5. No application code changes are required for the deploy to remain functional.
6. Subsequent PRs add `org_id` filter to repositories incrementally.

**Zero-downtime guarantee:** Step 4's DEFAULT means no backfill query is needed.
The column population happens at insert time for new rows; existing rows get the
default at migration time via `ALTER TABLE ... SET DEFAULT`.

---

## 3. Table Inventory

### Core tables (migrations/*)

| Table | PK | Contains customer data? | Tenant strategy | Migration note |
|-------|----|------------------------|-----------------|----------------|
| `users` | `id` UUID | Yes — email, role, dept, OIDC identity | Add `org_id`, FK to `organizations` | FK constraint + index |
| `audit_logs` | `id` UUID | Yes — user requests, PII detection, model usage | Add `org_id` (global chain preserved) | DEFAULT + index `(org_id, created_at)` |
| `budgets` | `user_id` FK→users | Yes — monthly limits, usage | Inherit from users.org_id via JOIN; no direct column needed initially | Phase 2: add org_id for org-level budget aggregation |
| `policies` | `id` | Yes — firewall rules per model/endpoint | Add `org_id` | One policy set per org |
| `audit_purge_runs` | `id` | Yes — purge evidence | Add `org_id` | Global admin can run cross-org purge |
| `audit_chain_anchors` | `id` UUID | Audit evidence | **Global — no tenant filter** | See D3 |
| `internal_db_sources` | `id` UUID | Potentially sensitive DB creds | Add `org_id` | Admin-managed per org |
| `schema_migrations` | `version` | No | No change | Migration tracking is global |

### Enterprise tables (migrations-enterprise/*)

| Table | PK | Contains customer data? | Tenant strategy |
|-------|----|------------------------|-----------------|
| `user_erasure_runs` | `id` UUID | Yes — DSAR PII evidence | Add `org_id` |
| `admin_event_logs` | `id` UUID | Yes — admin actions | Add `org_id`; global_admin events get `target_org_id` |
| `provider_governance_policies` | `id` UUID | Yes — provider allowlists | Add `org_id`; one active policy per org |
| `legal_holds` | `id` UUID | Yes — legal hold case data | Add `org_id`; strict isolation |
| `legal_hold_events` | `id` UUID | Yes — hold lifecycle events | Add `org_id` |

### New table: `organizations`

```sql
CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(256) NOT NULL,
    slug        VARCHAR(128) UNIQUE NOT NULL,
    is_active   BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Default org for single-tenant deployments.
INSERT INTO organizations (id, name, slug)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default');
```

---

## 4. Handler / API Path Inventory

### Auth paths

| Path | Current behavior | Tenant source | Post-T2 behavior |
|------|-----------------|---------------|-----------------|
| `POST /api/auth/login` | Validates user | `users.org_id` | JWT includes `org_id` claim |
| `POST /api/auth/register` | Creates user | Request param or default org | `org_id` required in SaaS mode |
| `GET /api/auth/oidc/callback` | OIDC login | OIDC `org` claim or default | Map OIDC claim to org; create user in org |
| `POST /api/auth/break-glass` | Global admin JWT | **Global** | JWT: `org_id=null`, `break_glass=true`, `scope=global` |
| SCIM `/scim/v2/Users` | Provisions users | SCIM Bearer token → org | One SCIM endpoint per org (Bearer token scoped to org) |

### Proxy / LLM paths

| Path | Current behavior | Post-T2 |
|------|-----------------|---------|
| `POST /proxy/{provider}/...` | Audit write, budget check | Filter by `claims.org_id` |
| `GET /proxy/providers` | List all providers | List org-specific providers |
| `GET /proxy/firewall/status` | Global pipeline status | Per-org pipeline (if org has custom rules) |

### Admin / governance paths

| Path | Current behavior | Post-T2 |
|------|-----------------|---------|
| `GET /api/users` | List all users | List users in `claims.org_id` only |
| `PUT /api/users/{id}` | Update any user | Must be same org; global_admin can cross-org |
| `GET/PUT /api/governance/policy` | Single global policy | Per-org policy; global_admin can view all |
| `GET /api/audit/logs` | All audit logs | Filter by `claims.org_id`; global_admin: `?org_id=all` |
| `POST /api/legal-holds` | Creates in single ns | Tag with `claims.org_id` |
| `GET /api/admin-events` | All admin events | Filter by org; cross-org visible to global_admin only |

### CLI / ops tools

| Tool | Current behavior | Post-T2 |
|------|-----------------|---------|
| `audit-verify` | Global chain verify | `--org-id` optional; no filter = global |
| `audit-export-evidence` | Exports all data | `--org-id` required unless `global_admin` credentials |
| `audit-purge` | Purges by retention | Must specify `--org-id` or `--all-orgs` (global_admin only) |
| `migrate` | Applies all migrations | No change |

---

## 5. Auth Claims Extension (JWT)

After PR-T2, the JWT `Claims` struct gains:

```go
type Claims struct {
    UserID       string `json:"user_id"`
    Email        string `json:"email"`
    Role         string `json:"role"`  // "tenant_admin" | "global_admin" | "user" | ...
    OrgID        string `json:"org_id"` // "" for global_admin (no org restriction)
    Department   string `json:"department,omitempty"`
    MFAVerified  bool   `json:"mfa_verified,omitempty"`
    BreakGlass   bool   `json:"break_glass,omitempty"`
    TokenVersion int    `json:"tv"`
    jwt.RegisteredClaims
}
```

**OrgID semantics:**
- Non-empty: user is restricted to this org
- Empty string: only valid for `global_admin` and `break_glass` sessions
- Middleware rejects empty OrgID for non-global roles

---

## 6. Repository Filter Contract

All tenant-scoped repository methods must accept `orgID string` as a parameter.
Methods without `orgID` are either:
- Explicitly global (documented with `// global: no tenant filter`)
- Lookup by stable ID where tenant is verified via JOIN (e.g., `GetByID` verifies `users.org_id = claims.org_id`)

**Prohibited after PR-T2:** Any `SELECT ... FROM audit_logs` without `WHERE org_id = $N`
in a request-handling path. Exceptions allowed only in:
- `audit-verify` (global chain verification)
- `audit-export-evidence --org-id all` (global_admin only)
- Internal migration tooling

---

## 7. Open Questions

| # | Question | Owner | Deadline |
|---|----------|-------|---------|
| OQ-1 | WORM chain: when exporting per-tenant bundle, should the bundle README warn that global chain continuity is unverified? | RFC author | Before PR-T2 |
| OQ-2 | SCIM: one endpoint per org (different Bearer tokens) or single endpoint with `X-Org-ID` header? | Mikhail | Before PR-T2 |
| OQ-3 | Budget model: per-user within org, or per-org aggregate cap, or both? | Product | Before PR-T2 |
| OQ-4 | Global admin UI/CLI: should `audit-verify` auto-detect global_admin from JWT or require explicit `--global` flag? | Security | Before PR-T2 |
| OQ-5 | `internal_db_sources`: are these org-scoped or global? (Internal DB sources may be shared across orgs in some deployments) | Architecture | Before PR-T2 |

**Implementation must not begin until OQ-1 through OQ-5 are resolved.**

---

## 8. PR-T2 Implementation Breakdown

Implementation is phased to ensure zero-downtime and incremental testability.

### Phase 1: Schema + seed (1 migration, no code changes)
- Create `organizations` table with default row
- Add `org_id UUID NOT NULL DEFAULT '...'` to all tenant-scoped tables (see §3)
- No application changes required; existing queries continue to work
- Smoke test: `go test -tags 'enterprise smoke' ./smoke/...` must pass

### Phase 2: Auth claims + middleware
- Add `OrgID` to `Claims` struct
- `AuthMiddleware`: set `claims.OrgID` from `users.org_id`
- OIDC callback: map org claim to `users.org_id`
- SCIM provisioner: accept org context
- Tests: middleware unit tests + OIDC smoke

### Phase 3: Repository filters
- Add `orgID string` parameter to all tenant-scoped repo methods
- Pass `claims.OrgID` from handler → service → repo
- Global admin: `orgID = ""` passes through (no filter)
- Tests: TDD — write failing tests first, then implement

### Phase 4: Handler enforcement
- All non-global handlers: verify `claims.OrgID != ""` for non-global roles
- Global admin paths: require `role == "global_admin"`, log cross-org access
- Governance: per-org policy activation
- Tests: handler-level tests for cross-org rejection

### Phase 5: Evidence + export
- `audit-export-evidence`: add `--org-id` flag; require for non-global-admin
- `audit-verify`: add `--org-id` flag (optional; no filter = global)
- Bundle README: add per-tenant vs global disclaimer
- Tests: smoke `TestSmoke_WORM_ChainAnchorBundle` extended with org filter

### Phase 6: Smoke + runbook update
- Extend enterprise smoke: create two orgs, verify data isolation
- Update deploy checklist: org bootstrap steps
- Update break-glass runbook: note global scope

---

## 9. Acceptance Criteria

- [ ] `tenant_id` (as `org_id`) is always-on; every non-trivial table has a strategy
- [ ] Every user-visible API path is classified as tenant-scoped or global (§4)
- [ ] Every table with customer data has an explicit tenant strategy (§3)
- [ ] Single-tenant migration path is explicit: default org, DEFAULT value backfill
- [ ] Global admin behavior is auditable: cross-org actions logged with source + target org
- [ ] WORM/evidence verification semantics under tenant filter are defined (§D3)
- [ ] Break-glass is explicitly global (§D2)
- [ ] All open questions (§7) resolved before implementation begins
- [ ] No implementation starts until this RFC is signed off

---

## 10. Non-Goals for PR-T1/T2

- Multi-region data residency (separate RFC)
- Per-tenant encryption keys (separate RFC)
- Network-level isolation (K8s namespace per org)
- Billing/metering per org
- Organization hierarchy / sub-orgs

---

## 11. References

- PR-G3: Department/Sensitivity routing (tenant department is distinct from org isolation)
- PR-E2: SCIM sync (will be extended in Phase 2 to be org-scoped)
- PR-W5.1/5.2: WORM evidence bundle (affected by §D3)
- CLAUDE.md §CORE PRINCIPLE: "UBS — единственный источник истины о прошлом"

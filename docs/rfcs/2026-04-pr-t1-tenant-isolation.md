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

**Decision:**
- **Do NOT rename `admin` → `tenant_admin` in PR-T2.** The string `"admin"` is embedded
  in `RoleAdmin` constant, 15+ non-test call sites (`RequireRole(RoleAdmin)`, OIDC group
  mappings, SCIM role map, break-glass JWT). Renaming without an alias/migration plan
  breaks existing admins, OIDC/SCIM mappings, and break-glass. The rename is deferred
  to a separate optional breaking PR (PR-T3+) with a deprecation window.
- **In PR-T2:** `admin` = tenant-admin semantics (no change). Add `global_admin` string
  as a new role, valid only in JWT (not via normal registration). `NormalizeRole` rejects
  `global_admin` for normal user creation; it can only be set via admin API or direct DB
  by a global_admin.
- Cross-tenant actions by global_admin must be logged in `admin_event_logs` with
  `source_org_id` and `target_org_id` metadata fields.
- `support_admin` deferred to PR-T3.

Global admin must be explicitly granted; it cannot be auto-provisioned via OIDC
group mapping without `ALLOW_GLOBAL_ADMIN_OIDC_PROVISION=true` (dangerous override,
prod-validated).

Break-glass is **global by default** — it must produce a `break_glass_login_success`
event that includes `effective_tenant=global`. No tenant filter on break-glass JWT.

---

### D3: WORM chain canonical v2 requirement

**Finding (High):** The current HMAC chain canonical functions (v1) do not include
`org_id`. A DBA can change a chained row's `org_id` after insertion and move evidence
between tenants without any chain break. This makes tenant isolation cryptographically
unenforceable for WORM evidence.

**Decision:** Introduce canonical v2 for all tenant-aware chained rows.

```
v2|<existing_v1_fields>|<org_id>
```

- v1 rows (pre-T2) remain valid; verifier supports both v1 and v2 via prefix detection.
- Post-T2 `INSERT` always writes v2 canonical; verifier uses `row_hash` algorithm
  matching the stored `canonical_version` column (new column: `VARCHAR(4) DEFAULT 'v1'`).
- `CanonicalAuditLog`, `CanonicalAdminEventLog`, `CanonicalLegalHoldEvent`,
  `CanonicalAuditPurgeRun` all gain v2 variants that append `org_id`.
- PR-T2 Phase 3 (repository filters) must also update canonical writes.

**audit_purge_runs scope:** A global purge (across all orgs) must NOT be attributed to
the default org. Solution: add `scope VARCHAR(16) NOT NULL DEFAULT 'org'` column
(values: `'org'` | `'global'`) to `audit_purge_runs`. When `scope='global'`,
`org_id` is the global admin's org (informational only, not a filter). The canonical
v2 for purge runs includes `scope` field.

---

### D4: Per-tenant evidence bundle cryptographic design

**Finding (High):** The current bundle verifier (`bundle_verify.go:410`) compares
`anchor.row_count` with inventory entries in `[SeqLo, SeqHi]`. A per-tenant filtered
inventory would fail this check. Furthermore, Merkle roots are computed over the full
row set in a range — you cannot verify a Merkle root from a subset without either
inclusion proofs or the full digest inventory.

**Three options evaluated:**

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| A — Full digest inventory for intersecting ranges | Export all row hashes in intersecting anchor ranges, mark non-org rows with `"tenant":"other"` | Cryptographically complete; verifier unchanged | Leaks hashes of other orgs' rows |
| B — Merkle inclusion proofs per tenant row | For each org row, compute a Merkle proof against the anchor root | Clean tenant isolation; standard pattern | Significant implementation complexity; no existing infrastructure |
| C — Tenant-specific anchors | Run a separate anchor scheduler per org | Strongest isolation | Breaks global chain continuity; cannot verify cross-tenant ordering |

**Decision: Option A — Full digest inventory for intersecting ranges.**

The per-tenant bundle contains:
- All anchors whose `[SeqLo, SeqHi]` range intersects org rows
- The full `chain_inventory` (all row hashes) for those anchor ranges, with an `org_id`
  field per entry so the verifier can filter
- README clearly states: "Hashes of other orgs' rows are present for Merkle verification
  purposes. They are opaque (no payload) and prove only the position in the global
  chain, not the content of other organizations."

The bundle verifier (`VerifyBundle`) is extended to accept an optional `org_id` filter:
- `InventoryCount` check: when `org_id` filter is set, compare org row count against
  `anchor.row_count` is skipped (mismatch is expected); instead, verify that org rows
  are present and their row_hashes match the global inventory.
- Signature verification remains unchanged (anchors are global).
- File integrity check unchanged.

**Compliance note:** Option A means cross-tenant row hashes are visible in the bundle.
This is acceptable because row_hash is a cryptographic commitment (HMAC output), not
plaintext data. The org cannot reconstruct other orgs' row content from the hash.

---

### D5 (was D4): Migration strategy for existing single-tenant deployments

1. Add `org_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001'` to all tenant-scoped tables.
2. Add `canonical_version VARCHAR(4) NOT NULL DEFAULT 'v1'` to chained tables.
3. Add `scope VARCHAR(16) NOT NULL DEFAULT 'org'` to `audit_purge_runs`.
4. Migration is additive (no DROP, no breaking NOT NULL without DEFAULT) — safe for rolling restart.
5. Seed migration inserts the default org row into a new `organizations` table.
6. All existing rows automatically belong to the default org via the DEFAULT value.
7. No application code changes are required for the deploy to remain functional.
8. Subsequent PRs add `org_id` filter to repositories incrementally.

**Zero-downtime guarantee:** DEFAULT values mean no backfill query is needed.
Existing rows get the default at migration time via `ALTER TABLE ... SET DEFAULT`.

---

## 3. Table Inventory

### Core tables (migrations/*)

| Table | PK | Contains customer data? | Tenant strategy | Migration note |
|-------|----|------------------------|-----------------|----------------|
| `users` | `id` UUID | Yes — email, role, dept, OIDC identity | Add `org_id`, FK to `organizations` | FK constraint + index |
| `audit_logs` | `id` UUID | Yes — user requests, PII detection, model usage | Add `org_id` (global chain preserved) | DEFAULT + index `(org_id, created_at)` |
| `budgets` | `user_id` FK→users | Yes — monthly limits, usage | Inherit from users.org_id via JOIN; no direct column needed initially | Phase 2: add org_id for org-level budget aggregation |
| `policies` | `id` | Yes — firewall rules per model/endpoint | Add `org_id` | One policy set per org |
| `audit_purge_runs` | `id` | Yes — purge evidence | Add `org_id` + `scope VARCHAR(16) DEFAULT 'org'` | `scope='global'` for cross-org admin purge (see D3) |
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

Every user-visible API path must be classified before PR-T2 implementation begins.
Legend: **T** = tenant-scoped (filter by `claims.org_id`), **G** = global (no org filter),
**GA** = global_admin only, **PUB** = unauthenticated.

### Health / readiness (global, unauthenticated)

| Path | Class | Post-T2 behavior |
|------|-------|-----------------|
| `GET /api/health` | PUB | No change; reports DB/Redis connectivity only |
| `GET /api/ready` | PUB | No change; Kubernetes readiness probe |

### Auth paths

| Path | Class | Tenant source | Post-T2 behavior |
|------|-------|---------------|-----------------|
| `POST /api/auth/login` | T | `users.org_id` | JWT includes `org_id` claim |
| `POST /api/auth/register` | T | Request param or default org | `org_id` required in SaaS mode |
| `GET /api/auth/oidc/login` | T | N/A (redirect start) | Pass `org_id` hint via state cookie |
| `GET /api/auth/oidc/callback` | T | OIDC `org` claim or default | Map OIDC claim to org; create user in org |
| `POST /api/auth/break-glass` | GA | **Global** | JWT: `org_id=""`, `break_glass=true`, `scope=global` |
| `POST /api/auth/mfa/setup` | T | `claims.org_id` | No change; MFA is per-user not per-org |
| `POST /api/auth/mfa/verify` | T | `claims.org_id` | No change |
| `GET /api/auth/mfa/status` | T | `claims.org_id` | No change |

### SCIM provisioning

| Path | Class | Tenant source | Post-T2 behavior |
|------|-------|---------------|-----------------|
| `GET /scim/v2/Users` | T | SCIM Bearer token → org | One Bearer token scoped to one org |
| `POST /scim/v2/Users` | T | SCIM Bearer token → org | Provision into token's org |
| `GET /scim/v2/Users/{id}` | T | SCIM Bearer token → org | Returns user only if same org |
| `PUT /scim/v2/Users/{id}` | T | SCIM Bearer token → org | Update only in token's org |
| `PATCH /scim/v2/Users/{id}` | T | SCIM Bearer token → org | Patch only in token's org |
| `DELETE /scim/v2/Users/{id}` | T | SCIM Bearer token → org | Deprovision only in token's org |

### Proxy / LLM paths

| Path | Class | Post-T2 behavior |
|------|-------|-----------------|
| `POST /proxy/{provider}/...` | T | Audit write, budget check — filter by `claims.org_id` |
| `GET /proxy/providers` | T | List org-specific active providers |
| `GET /proxy/providers/test` | T | Test org's provider config (admin only within org) |
| `GET /proxy/firewall/status` | T | Per-org pipeline status (global_admin sees all) |

### Audit / evidence paths

| Path | Class | Post-T2 behavior |
|------|-------|-----------------|
| `GET /api/audit/logs` | T | Filter by `claims.org_id`; global_admin: `?org_id=all` or `?org_id=<uuid>` |
| `GET /api/audit/status` | T | WORM chain health for org's rows; global_admin: all tables |
| `GET /api/audit/export` | T/GA | `--org-id` required for non-global-admin; GA can omit for full export |

### Admin / governance paths

| Path | Class | Post-T2 behavior |
|------|-------|-----------------|
| `GET /api/users` | T | List users in `claims.org_id` only |
| `GET /api/users/{id}` | T | Must be same org; global_admin can cross-org |
| `PUT /api/users/{id}` | T | Must be same org; global_admin can cross-org |
| `DELETE /api/users/{id}` | T | Must be same org; global_admin can cross-org |
| `GET /api/admin-events` | T | Filter by org; cross-org visible to global_admin only |
| `GET/PUT /api/governance/policy` | T | Per-org policy; global_admin can view/set any |
| `GET /api/governance/providers` | T | Org's allowed provider list |

### Internal DB sources

| Path | Class | Post-T2 behavior |
|------|-------|-----------------|
| `GET /api/internal-dbs` | T | List org's DB sources (admin only) |
| `POST /api/internal-dbs` | T | Create DB source for org |
| `GET /api/internal-dbs/{id}` | T | Must be same org |
| `PUT /api/internal-dbs/{id}` | T | Must be same org |
| `DELETE /api/internal-dbs/{id}` | T | Must be same org |
| `POST /api/internal-dbs/{id}/test` | T | Test connectivity within org (admin only) |

### Legal hold paths

| Path | Class | Post-T2 behavior |
|------|-------|-----------------|
| `POST /api/legal-holds` | T | Creates hold tagged with `claims.org_id` |
| `GET /api/legal-holds` | T | List holds for `claims.org_id` |
| `GET /api/legal-holds/{id}` | T | Must be same org |
| `POST /api/legal-holds/{id}/approve` | T | 4-eyes: approver must be same org |
| `POST /api/legal-holds/{id}/release` | T | Must be same org |
| `POST /api/legal-holds/{id}/evidence` | T | Evidence export scoped to org |
| `GET /api/legal-holds/{id}/events` | T | Lifecycle events for this hold (same org) |

### Dashboard / frontend API

| Path | Class | Post-T2 behavior |
|------|-------|-----------------|
| `GET /api/dashboard/stats` | T | Org-scoped counts (users, audit logs, budget usage) |
| `GET /api/dashboard/usage` | T | Org-scoped model usage aggregation |

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
    Role         string `json:"role"`  // "admin" | "global_admin" | "user" | ...
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

| # | Question | Owner | Deadline | Status |
|---|----------|-------|---------|--------|
| ~~OQ-1~~ | ~~WORM chain: bundle README warn about global chain continuity?~~ | RFC author | — | **Closed** — answered in D4: Option A exports full digest inventory; README disclaimer is mandatory and wording is specified in D4 |
| OQ-2 | SCIM: one endpoint per org (different Bearer tokens) or single endpoint with `X-Org-ID` header? | Mikhail | Before PR-T2 | Open |
| OQ-3 | Budget model: per-user within org, or per-org aggregate cap, or both? | Product | Before PR-T2 | Open |
| OQ-4 | Global admin UI/CLI: should `audit-verify` auto-detect global_admin from JWT or require explicit `--global` flag? | Security | Before PR-T2 | Open |
| OQ-5 | `internal_db_sources`: are these org-scoped or global? (Internal DB sources may be shared across orgs in some deployments) | Architecture | Before PR-T2 | Open |
| OQ-6 | Per-tenant bundle Merkle validation: Option A exports all row hashes in anchor ranges (including other-org rows). Should PR-T2 Phase 5 implement the full Merkle subset proof path in `VerifyBundle`, or is the current "skip `InventoryCount` check for filtered bundles" approach acceptable for the initial release? The subset-proof path would require storing Merkle tree sibling nodes per anchor, which is a non-trivial schema change. | Architecture | Before PR-T2 Phase 5 | Open |

**Implementation must not begin until OQ-2 through OQ-6 are resolved.**

---

## 8. PR-T2 Implementation Breakdown

Implementation is phased to ensure zero-downtime and incremental testability.

### Phase 1: Schema + seed (1 migration, no code changes)
- Create `organizations` table with default row
- Add `org_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001'` to all tenant-scoped tables (see §3)
- Add `canonical_version VARCHAR(4) NOT NULL DEFAULT 'v1'` to all chained tables (`audit_logs`, `admin_event_logs`, `legal_hold_events`, `audit_purge_runs`)
- Add `scope VARCHAR(16) NOT NULL DEFAULT 'org'` to `audit_purge_runs` (see D3)
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

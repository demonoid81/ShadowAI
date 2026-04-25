# ShadowAI Enterprise — database migrations

Enterprise Components database schema (see `/ENTERPRISE.md` and
`/LICENSE.enterprise`).

These SQL files are covered by the **ShadowAI Enterprise License**,
not by Apache 2.0.

## Applying

Enterprise operators must apply these migrations IN ADDITION to
`/backend/migrations/`:

```bash
# Core schema (always)
psql "$DATABASE_URL" -f backend/migrations/001_*.sql
# ... through 008_*.sql

# Enterprise schema (only when running enterprise build):
psql "$DATABASE_URL" -f backend/migrations-enterprise/009_*.sql
# ... through 012_*.sql
```

Numbering is continuous (009→012) so the audit trail of schema
versions stays linear across a full build. Core-only operators simply
stop at 008.

## Current migrations

- `009_create_user_erasure_runs.sql` — DSAR tombstone table (PR-B).
- `010_create_admin_event_logs.sql` — admin access audit storage (PR-D).
- `011_add_target_to_audit_purge_runs.sql` — retention target column (PR-D.1).
- `012_create_provider_governance_policies.sql` — Provider/Model Governance
  policy singleton (PR-G1).
- `013_create_legal_holds.sql` — legal hold groundwork (PR-L1).
- `014_add_role_rules_to_governance_policies.sql` — role-based governance
  (PR-G2).
- `015_legal_hold_status_four_eyes.sql` — 4-eyes approver workflow (PR-L2.3).
- `016_add_chain_fields_and_legal_hold_events.sql` — tamper-evident chain for
  admin_event_logs + legal_hold_events (PR-W2).
- `017_add_context_rules_to_governance_policies.sql` — context-scoped governance
  (PR-G3).
- `018_tenant_schema_seed_enterprise.sql` — tenant isolation: org_id on all
  enterprise tables, source_org_id/target_org_id/canonical_version on
  admin_event_logs, scim_tokens table (PR-T2.1). **Depends on core migration
  018.**

## If you run Core-only build

Do **not** apply these migrations. The enterprise-only tables
(`user_erasure_runs`, `admin_event_logs`, `provider_governance_policies`,
`legal_holds`, `legal_hold_events`, `scim_tokens`) won't be created, and no
Core-build code path references them.

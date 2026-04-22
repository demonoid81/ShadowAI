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

- `009_create_user_erasure_runs.sql` — DSAR tombstone table
  (PR-B).
- `010_create_admin_event_logs.sql` — admin access audit storage
  (PR-D).
- `011_add_target_to_audit_purge_runs.sql` — retention target
  column (PR-D.1).
- `012_create_provider_governance_policies.sql` — Provider/Model
  Governance policy singleton (PR-G1).

## If you run Core-only build

Do **not** apply these migrations. The enterprise-only tables
(`user_erasure_runs`, `admin_event_logs`,
`provider_governance_policies`) won't be created, and no Core-build
code path references them.

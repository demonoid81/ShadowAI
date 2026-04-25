# ShadowAI Tenant Isolation — Operator Runbook

**Version:** T2.5 (2026-04-25)
**Applies to:** Enterprise deployments with multi-tenant isolation enabled (T2.1+)

---

## Overview

ShadowAI T2.x implements always-on tenant isolation. Every deploy (including
single-tenant self-hosted) has a default org (`00000000-0000-0000-0000-000000000001`).
In multi-tenant deployments, each customer organisation is an independent org with
isolated users, audit logs, policies, and evidence.

---

## 1. Tenant Provisioning

### Create a new organisation

```sql
INSERT INTO organizations (id, name, slug)
VALUES (gen_random_uuid(), 'Acme Corp', 'acme')
RETURNING id;
```

Save the returned UUID as `<ORG_ID>`.

### Provision the first admin user

```sql
-- After the user registers via API, move them to the org:
UPDATE users SET org_id = '<ORG_ID>' WHERE email = 'admin@acme.com';
```

Or provision via SCIM (see §3).

---

## 2. JWT / Auth

Every authenticated session carries `org_id` in the JWT claims (set from
`users.org_id` by `AuthMiddleware` after DB lookup). JWT payload is not the
source of truth — middleware always refreshes from DB.

**Break-glass sessions** have `org_id = ""` (global scope). Break-glass can
read global audit/admin-events lists.

**Normal admin/user** sessions are restricted to their `org_id`.

---

## 3. SCIM Token Setup (per org)

Each org must have its own SCIM Bearer token registered in `scim_tokens`.

### Register a token for an org

```bash
# 1. Generate a secure token
TOKEN=$(openssl rand -hex 32)
echo "SCIM Bearer token: $TOKEN"

# 2. Hash it (SHA-256 hex)
TOKEN_HASH=$(echo -n "$TOKEN" | sha256sum | awk '{print $1}')

# 3. Insert into scim_tokens
psql "$DATABASE_URL" <<SQL
INSERT INTO scim_tokens (org_id, token_hash, label)
VALUES ('<ORG_ID>', '$TOKEN_HASH', 'acme-primary');
SQL

# 4. Store $TOKEN in your IdP SCIM connector as the Bearer token.
# Never store the plaintext token in the database.
```

### Use the token

Configure your IdP's SCIM connector to send:
```
Authorization: Bearer <TOKEN>
```

The SCIM endpoint resolves `org_id` from the token on every request.

### Rotate a token

```sql
-- Deactivate old token
UPDATE scim_tokens SET is_active = false WHERE id = '<TOKEN_ID>';
-- Insert new token (repeat registration steps above)
```

---

## 4. Governance Policy (per org)

Each org has its own active governance policy. Default: `disabled` (all allowed).

### Set policy via API

```bash
curl -X PUT "$API_URL/api/governance/policy" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "allowlist_strict",
    "rules": [
      {"provider": "openai", "models": ["gpt-4o-mini", "gpt-4o"]},
      {"provider": "anthropic", "models": ["claude-3-haiku"]}
    ]
  }'
```

Policy is scoped to the `org_id` from the JWT.

---

## 5. Audit Log Export (per tenant)

**Always use `--org-id` for tenant exports. `--global` is privileged.**

```bash
# Tenant export (recommended)
audit-export-evidence \
  --output /secure/exports/acme-$(date +%Y%m%d) \
  --org-id <ORG_ID> \
  --pubkey-file /etc/shadowai/anchor-pubkey.b64

# Global export (privileged)
audit-export-evidence \
  --output /secure/exports/global-$(date +%Y%m%d) \
  --global \
  --pubkey-file /etc/shadowai/anchor-pubkey.b64
```

**Tenant bundle** contains:
- `anchors.jsonl` — anchor ranges intersecting org's rows
- `chain_inventory.jsonl` — full digest inventory for those ranges (includes cross-tenant hashes for Merkle recomputation — opaque HMAC outputs, no row content)
- `bundle_manifest.json` with `org_id` field
- `README.txt` with tenant disclaimer (no global verification reports)

---

## 6. Audit Purge (per tenant)

**Always specify `--org-id` or `--all-orgs`. Without scope → exit 2.**

```bash
# Tenant purge (audit_logs for one org)
audit-purge --retention-days 90 --org-id <ORG_ID> --target audit_logs

# Tenant purge (admin events for one org)
audit-purge --retention-days 365 --org-id <ORG_ID> --target admin_event_logs

# Global purge (PRIVILEGED — affects all tenants)
audit-purge --retention-days 90 --all-orgs --target audit_logs
```

Evidence record in `audit_purge_runs`:
- `org_id` = target org (or DefaultOrgID for global)
- `scope` = `'org'` | `'global'`
- `canonical_version` = `'v2'` (HMAC chain covers org_id + scope)

---

## 7. Operator Warnings

| Operation | Risk | Required flag |
|-----------|------|---------------|
| `audit-purge` | **Irreversible** — deletes rows | `--org-id` or `--all-orgs` |
| `audit-export-evidence` | Evidence exposure | `--org-id` or `--global` |
| `--all-orgs` / `--global` | Cross-tenant data access | Explicit privileged flag |
| SCIM token without org | Creates users in default org | Register in `scim_tokens` |
| Break-glass login | Emergency global access | All actions audited |

---

## 8. Tenant Isolation Verification

```bash
cd backend
go test -tags 'enterprise smoke' ./smoke/... -run TestSmoke_TenantIsolation \
  -count=1 -v -timeout 15m
```

6 scenarios: user repo isolation, SCIM syncer, governance per-org, audit log
filtering, admin event filtering, tenant purge + export.

---

---

## 9. Org-Level Budget Caps (G4)

Each org can have a monthly spend cap configured via the API.

### Mode semantics

| Mode | Blocks requests? | Records actual spend? | Use case |
|------|-----------------|-----------------------|----------|
| `disabled` | ✗ | ✓ | Safe rollout: collect baseline data without risk |
| `observe` | ✗ | ✓ + soft-exceeded event | Visibility: alert on over-cap without enforcing |
| `enforce` | ✓ at cap | ✓ | Hard enforcement: block when projected spend ≥ cap |

**Rollout path:** `disabled → observe → enforce`

1. Start with `disabled` to collect baseline spend data for 1–2 billing cycles.
2. Switch to `observe` to see soft-exceeded alerts without blocking production traffic.
3. Switch to `enforce` once you have confidence in the limit value.

### Set org budget via API

```bash
# Step 1: collect baseline (no blocking)
curl -X PUT "$API_URL/api/orgs/$ORG_ID/budget" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"mode":"disabled","monthly_limit_cents":500000}'

# Step 2: observe mode (soft alerts only)
curl -X PUT "$API_URL/api/orgs/$ORG_ID/budget" \
  -d '{"mode":"observe","monthly_limit_cents":500000}'

# Step 3: enforce hard cap
curl -X PUT "$API_URL/api/orgs/$ORG_ID/budget" \
  -d '{"mode":"enforce","monthly_limit_cents":500000}'
```

`monthly_limit_cents = 0` means unlimited (cap disabled regardless of mode).

### Prometheus spend baseline

```promql
# Total spend across all orgs (all modes)
rate(shadowai_org_budget_spent_cents_total[30d])

# Budget decisions by outcome
sum by (decision, mode) (shadowai_org_budget_decisions_total)

# Soft-exceeded events (observe mode over cap)
increase(shadowai_org_budget_decisions_total{decision="soft_exceeded"}[1d])
```

---

## 10. Roadmap Status (2026-04-26)

| PR | Component | Status |
|----|-----------|--------|
| T2.1 Schema Seed | organizations, org_id columns, scim_tokens | ✅ Complete |
| T2.2 Auth Claims | JWT.OrgID from DB, fail-closed middleware | ✅ Complete |
| T2.3 Repo Filters | users/audit/governance/internaldb/SCIM org filters | ✅ Complete |
| T2.4 CLI Tenant | audit-purge --org-id, audit-export --org-id, canonical v2 | ✅ Complete |
| T2.5 E2E Smoke | 6-scenario tenant isolation smoke suite | ✅ Complete |
| T2.6 Control Plane | global_admin org/SCIM management API | ✅ Complete |
| G4 Org Budget | disabled/observe/enforce + atomic reserve | ✅ Complete |

**Next:**
- T3/W6: Merkle subset proof (no cross-tenant hashes in tenant bundle)
- G4.3: Budget alerts + webhook notifications
- T2.6: global_admin role enforcement + cross-org admin UI

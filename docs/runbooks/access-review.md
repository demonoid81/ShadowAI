# Access Review Runbook (SOC2.3)

`audit-access-review` generates a period-scoped access review report for compliance
evidence. It queries the database directly — no external IdP calls required.

---

## When to run

- **Quarterly**: before each SOC 2 audit window (Q1/Q2/Q3/Q4)
- **After personnel changes**: admin role changes, deprovisioning events
- **After security incidents**: any break-glass usage must be formally reviewed

---

## Tenant vs global mode

| Mode | Flag | Shows | Use case |
|------|------|-------|---------|
| Tenant | `--org-id <uuid>` | Users of that org only | Per-tenant compliance review |
| Global | `--global` | All orgs, cross-org privileged view | Platform-wide security review |

Tenant mode strictly filters by org_id — users of other orgs are never visible.
Global mode includes all users and explicitly highlights `global_admin` accounts.

---

## Quarterly review flow

### Step 1: Set environment

```bash
export DATABASE_URL="postgres://user:pass@host/shadowai_prod"
```

### Step 2: Run tenant review (per-org)

```bash
audit-access-review \
  --org-id aaaaaaaa-0000-4000-8000-000000000001 \
  --from 2026-01-01 --to 2026-03-31 \
  --require-admin-mfa \
  --format json \
  --output ./access-review-Q1-2026-org-a.json
```

### Step 3: Run global review

```bash
audit-access-review \
  --global \
  --from 2026-01-01 --to 2026-03-31 \
  --require-admin-mfa \
  --require-idp-link \
  --format json \
  --output ./access-review-Q1-2026-global.json
```

### Step 4: Review findings

```bash
# Show all findings:
cat ./access-review-Q1-2026-global.json | jq '.findings[] | {code, severity, description, count}'

# Show specific finding:
cat ./access-review-Q1-2026-global.json | jq '.findings[] | select(.code == "break_glass_used")'

# Show admins without MFA:
cat ./access-review-Q1-2026-global.json | jq '.admins_without_mfa[] | {id, email, role}'
```

### Step 5: Print table summary

```bash
audit-access-review --global --from 2026-01-01 --to 2026-03-31 --format table
```

---

## Exit codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Report generated, no policy findings | Review complete; file as evidence |
| 1 | Findings present — review required | See findings section; remediate before filing |
| 2 | Config or DB error | Check DATABASE_URL, fix flags |

---

## Policy flags

| Flag | Effect |
|------|--------|
| `--require-admin-mfa` | Finding (critical) if any admin lacks MFA enrollment |
| `--require-idp-link` | Finding (high) if any admin lacks OIDC/SCIM linkage |
| Neither | Findings only for: global_admin present, break-glass used, inactive privileged |

---

## Findings and remediation

### `global_admin_present` (high)

Global admin accounts bypass tenant isolation. Always a finding; requires acknowledgement.

**Remediation**:
- Review each global_admin account
- Confirm operational necessity (on-call, break-glass backup)
- Remove role if no longer required
- Document remaining accounts with justification

### `admin_without_mfa` (critical / medium)

Admin without MFA enrollment is a high-risk access control gap.

**Remediation**:
- Require TOTP enrollment within 7 days
- Disable account after policy window expires
- Use `--require-admin-mfa` to enforce in future reviews

### `break_glass_used` (high)

Emergency access was used in the review period. Always a finding — must be reviewed.

**Remediation**:
1. Identify each break-glass event (actor_user_id, action, timestamp)
2. Confirm the emergency was authorized (incident ticket, CAB approval)
3. Rotate break-glass credentials after use
4. Document the incident in the security incident log

### `inactive_privileged` (critical)

Inactive user (is_active=false) still has admin/global_admin role.

**Remediation**:
- Remove privileged role from inactive accounts immediately
- Or deprovision the account permanently via erasure flow
- Verify SCIM/IdP deprovisioning is synchronized

### `unlinked_admin` (high) — requires `--require-idp-link`

Admin without OIDC or SCIM linkage bypasses IdP-controlled lifecycle.

**Remediation**:
- Link account to corporate IdP via OIDC or SCIM provisioning
- If intentional (service account), document and exclude from policy
- Consider making `--require-idp-link` a standing policy

---

## Report fields

| Field | Description |
|-------|-------------|
| `manifest` | Generated at, period, scope, org_id, build commit |
| `users_summary` | Counts: total, active, inactive, admins, global_admins, with_mfa, oidc_linked, scim_linked, unlinked |
| `privileged_users` | All admin + global_admin users |
| `global_admins` | global_admin role only |
| `org_admins` | admin role (org-scoped) |
| `admins_without_mfa` | Admins with mfa_required=false OR no TOTP enrolled |
| `oidc_linked_users` | Users with OIDC issuer set |
| `scim_linked_users` | Users with SCIM external_id set |
| `unlinked_users` | Users with neither OIDC nor SCIM |
| `inactive_users` | is_active=false |
| `break_glass_events` | Admin events with break_glass=true in period |
| `findings` | Policy violations requiring action |

**Privacy notes**:
- OIDC subject is NOT included in the report (masked as SHA256 hash prefix)
- API keys, TOTP secrets, passwords are never exported
- SCIMExternalID presence is boolean (linked/not linked), not the raw ID

---

## Integration with SOC2.1 evidence package

`audit-collect-evidence` automatically runs the global access review when `DATABASE_URL`
is set. The report is saved as `evidence/access-review.json` in the package:

```bash
audit-collect-evidence \
  --from 2026-01-01 --to 2026-03-31 \
  --output ./evidence-Q1-2026.zip --format zip
```

The manifest will show `access_review: collected` if successful.

To attach a per-tenant review instead:
```bash
# Run per-tenant review separately
audit-access-review \
  --org-id <uuid> --from 2026-01-01 --to 2026-03-31 \
  --format json --output ./evidence-Q1-2026-tenant-a.json

# Attach to the evidence package directory
cp ./evidence-Q1-2026-tenant-a.json ./evidence-Q1-2026/evidence/
```

---

## Related documents

- [`docs/compliance/soc2-iso-control-mapping.md`](../compliance/soc2-iso-control-mapping.md) — SOC2 control §1
- [`docs/runbooks/evidence-collection.md`](evidence-collection.md) — SOC2.1/SOC2.2
- [`docs/production-hardening.md`](../production-hardening.md) — mandatory secrets and alerts

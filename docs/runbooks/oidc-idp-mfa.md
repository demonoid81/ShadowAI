# OIDC IdP MFA Enforcement Runbook (PR-E3)

## Overview

ShadowAI can enforce that admin users authenticate with MFA at the IdP level,
not just with their password. When `OIDC_REQUIRE_MFA_FOR_ADMIN=true`, OIDC
callbacks for admin-role users are rejected if the ID token does not contain
MFA-confirming `amr` or `acr` claims.

The issued internal JWT carries `mfa_verified=true` when MFA is confirmed,
which satisfies `ADMIN_MFA_REQUIRED` without requiring a separate TOTP challenge.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_REQUIRE_MFA_FOR_ADMIN` | `false` | Reject admin OIDC logins without IdP MFA |
| `OIDC_MFA_AMR_VALUES` | `mfa,otp,hwk,swk` (when require=true) | AMR values confirming MFA |
| `OIDC_MFA_ACR_VALUES` | `` | ACR values confirming MFA (supplemental) |

---

## Okta Configuration

### What claims Okta sends

Okta includes `amr` in the ID token when the user authenticates with MFA:
```json
{"amr": ["mfa", "pwd"]}       // password + any MFA factor
{"amr": ["otp", "pwd"]}       // TOTP
{"amr": ["hwk", "pin"]}       // hardware key (FIDO2)
```

### Okta MFA policy setup

1. In Okta Admin → Security → Authentication → Sign On Policies:
   - Create a policy targeting your ShadowAI application
   - Add a rule: **IF role is admin (or group is shadowai-admins) → require MFA**
   - MFA methods: Okta Verify, FIDO2 Security Key, TOTP

2. Verify AMR is included in ID tokens:
   - Okta Admin → Applications → ShadowAI → Sign On → Edit
   - Enable: "Include `amr` in ID token"

3. ShadowAI config:
   ```bash
   OIDC_REQUIRE_MFA_FOR_ADMIN=true
   OIDC_MFA_AMR_VALUES=mfa,otp,hwk,swk  # default — works for all Okta MFA types
   ```

### Okta AMR reference

| MFA Method | AMR values |
|------------|-----------|
| Okta Verify (push/TOTP) | `mfa`, `otp` |
| FIDO2/WebAuthn | `hwk` (hardware), `swk` (platform) |
| SMS | `sms` |
| Email OTP | `email` |

---

## Azure Active Directory Configuration

### What claims Azure AD sends

Azure AD sets `amr` when MFA policies are enforced:
```json
{"amr": ["mfa"]}          // MFA performed (generic)
{"amr": ["mfa", "rsa"]}   // MFA + RSA device
```

Azure AD also supports ACR via Conditional Access policies:
```json
{"acr": "urn:microsoft:policies:mfa"}
```

### Azure AD MFA policy setup

1. Azure Portal → Azure Active Directory → Conditional Access:
   - New policy targeting ShadowAI enterprise application
   - Users: **Admin group** (e.g. `shadowai-admins`)
   - Cloud apps: ShadowAI
   - Grant: **Require multi-factor authentication**

2. Verify `amr` claim is included:
   - Azure AD → App Registrations → ShadowAI → Token configuration
   - Add optional claim: `amr` (for ID tokens)

3. ShadowAI config:
   ```bash
   OIDC_REQUIRE_MFA_FOR_ADMIN=true
   OIDC_MFA_AMR_VALUES=mfa,rsa            # Azure AD sends these
   # OR use ACR if using Conditional Access policy:
   OIDC_MFA_ACR_VALUES=urn:microsoft:policies:mfa
   ```

---

## Google Workspace Configuration

### What claims Google sends

Google Workspace uses `acr` for MFA indication rather than `amr`:
```json
{"acr": "http://schemas.openid.net/pape/policies/2007/06/multi-factor"}
```

Or with 2-Step Verification enforced:
```json
{"amr": ["otp"]}
```

### Google Workspace setup

1. Google Admin Console → Security → 2-Step Verification:
   - Enforcement: **On for everyone** (or specific OU with admins)
   - Allow users to turn off 2-Step Verification: **No**

2. ShadowAI config:
   ```bash
   OIDC_REQUIRE_MFA_FOR_ADMIN=true
   OIDC_MFA_AMR_VALUES=otp,hwk
   OIDC_MFA_ACR_VALUES=http://schemas.openid.net/pape/policies/2007/06/multi-factor
   ```

---

## Troubleshooting

### Admin login fails with `admin_mfa_required`

1. Check the admin event log:
   ```bash
   curl -H "Authorization: Bearer $ADMIN_TOKEN" \
     '/api/admin-events?action=oidc_mfa_not_confirmed'
   ```
   The event includes `amr`, `acr`, `required_amr`, `required_acr` fields.

2. Verify what claims your IdP is actually sending:
   - Use jwt.io to decode the raw ID token
   - Check `amr` and `acr` fields
   - Compare against `OIDC_MFA_AMR_VALUES`

3. Common issues:
   - **IdP not sending `amr`**: Enable AMR in your IdP's application settings
   - **AMR values don't match**: Add the IdP-specific value to `OIDC_MFA_AMR_VALUES`
   - **Admin hasn't enrolled MFA at IdP**: Enforce MFA enrollment in IdP policy

### All admin logins are blocked after enabling OIDC_REQUIRE_MFA_FOR_ADMIN

This happens when `OIDC_MFA_AMR_VALUES` and `OIDC_MFA_ACR_VALUES` are both
configured with values that don't match your IdP's claims.

Use break-glass for emergency access and then fix the configuration:

```bash
# Step 1: emergency break-glass login (see docs/runbooks/break-glass.md)
TOKEN=$(curl -sf -X POST https://api.shadowai.example.com/api/auth/break-glass \
  -H 'Content-Type: application/json' -d '{"secret":"..."}' | jq -r .token)

# Step 2: check admin events to see what AMR/ACR values were in the denied tokens
curl -H "Authorization: Bearer $TOKEN" \
  '/api/admin-events?action=oidc_mfa_not_confirmed' | jq .

# Step 3: update OIDC_MFA_AMR_VALUES to match your IdP's actual claims
kubectl patch secret shadowai-secrets \
  --patch='{"stringData":{"OIDC_MFA_AMR_VALUES":"<actual_amr_from_events>"}}'
kubectl rollout restart deployment/shadowai
```

### Non-admin users are unaffected

`OIDC_REQUIRE_MFA_FOR_ADMIN` only blocks admin-role users. Regular users
(`role=user`, `role=analyst`, `role=auditor`) can log in via OIDC without MFA
even when this flag is set. Per-user MFA can still be enforced via
`ADMIN_MFA_REQUIRED` for local (non-OIDC) sessions.

---

## Audit Events

| Event | Meaning |
|-------|---------|
| `oidc_login_login` | Successful OIDC login (no MFA confirmed or not required) |
| `oidc_login_synced` | Successful OIDC login with profile update |
| `oidc_mfa_not_confirmed` | Admin login denied: IdP claims didn't include MFA |

Fields in `oidc_mfa_not_confirmed` metadata:
- `amr` — token's AMR values (what IdP sent)
- `acr` — token's ACR value
- `required_amr` — configured `OIDC_MFA_AMR_VALUES`
- `required_acr` — configured `OIDC_MFA_ACR_VALUES`

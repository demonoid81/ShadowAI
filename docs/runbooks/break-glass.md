# ShadowAI Break-Glass Emergency Access Runbook

## What is Break-Glass?

Break-glass provides emergency admin access when the primary authentication path
(OIDC, MFA) is unavailable — e.g. IdP outage, compromised admin accounts, or a
production incident requiring immediate access without OIDC.

**Use break-glass only when all other access paths have failed.**

---

## Prerequisites

Break-glass must be configured before the incident:

```bash
# Generate a strong password (store in your password manager or sealed vault).
openssl rand -base64 32

# Generate the bcrypt hash.
# MinCost=12 (change to higher in prod for replay-resistance).
htpasswd -bnBC 12 "" '<YOUR_PASSWORD>' | tr -d ':\n'

# Set in K8s Secret (BEFORE the incident — can't do this during an outage).
kubectl create secret generic shadowai-secrets \
  --from-literal=breakGlassSecretHash='<BCRYPT_HASH>' \
  --dry-run=client -o yaml | kubectl apply -f -
```

And in values-prod.yaml:
```yaml
config:
  BREAK_GLASS_ENABLED: "true"
  BREAK_GLASS_JWT_TTL: "1h"
```

---

## Break-Glass Activation

### Who can approve?

Break-glass activation requires approval from:
1. Security team lead OR CTO
2. Documented in incident tracking system (Jira/Linear) before use

### Activation procedure

```bash
# 1. Log the activation (required).
INCIDENT_ID="INC-XXXX"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) BREAK_GLASS_ACTIVATED incident=${INCIDENT_ID} by=${OPERATOR}" \
  >> /var/log/shadowai-break-glass.log

# 2. Request break-glass token.
TOKEN=$(curl -sf -X POST https://api.shadowai.example.com/api/auth/break-glass \
  -H 'Content-Type: application/json' \
  -d '{"secret":"<BREAK_GLASS_PASSWORD>"}' | jq -r .token)

# Verify token has break_glass claim.
echo "${TOKEN}" | cut -d. -f2 | base64 -d 2>/dev/null | jq .break_glass
# Expected: true

# 3. Use the token for admin operations (1h TTL).
curl -H "Authorization: Bearer ${TOKEN}" https://api.shadowai.example.com/api/users

# 4. The token expires automatically after BREAK_GLASS_JWT_TTL (default 1h).
```

### What break-glass cannot do

- Break-glass token expires in 1h. Do NOT store it or re-use it.
- Break-glass has `break_glass=true` claim — all API calls are logged to admin_event_logs.
- Break-glass bypasses MFA but does NOT bypass RBAC (role=admin).

---

## Post-Incident Rotation (MANDATORY)

**Rotate the break-glass secret within 24h of any use.**

```bash
# 1. Generate new password.
NEW_PASSWORD=$(openssl rand -base64 32)
NEW_HASH=$(echo "${NEW_PASSWORD}" | htpasswd -bnBC 12 "" | tr -d ':\n')

# 2. Update K8s Secret.
kubectl patch secret shadowai-secrets \
  --patch="{\"stringData\":{\"breakGlassSecretHash\":\"${NEW_HASH}\"}}"

# 3. Store new password in vault (do NOT log the plaintext).
echo "Break-glass password rotated at $(date -u) for incident ${INCIDENT_ID}" \
  >> /var/log/shadowai-break-glass.log

# 4. Restart app to pick up new secret.
kubectl rollout restart deployment/shadowai

# 5. Verify old token is rejected (should return 401 after TTL or restart).
curl -sf -X POST https://api.shadowai.example.com/api/auth/break-glass \
  -H 'Content-Type: application/json' \
  -d '{"secret":"<OLD_PASSWORD>"}' && echo "ERROR: old token still works"
```

---

## MFA Management

### Enable MFA for an admin account

```bash
# Authenticated as the admin, POST /api/auth/mfa/setup
curl -X POST https://api.shadowai.example.com/api/auth/mfa/setup \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
# Returns: {"uri": "otpauth://totp/ShadowAI:admin@example.com?secret=..."}

# Scan the URI with an authenticator app (Google Authenticator, Authy, 1Password).

# Confirm with the first code from the app.
curl -X POST https://api.shadowai.example.com/api/auth/mfa/confirm \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"code":"123456"}'
# Returns: {"status":"mfa_enabled"}
```

### MFA login flow

```bash
# 1. Password login returns mfa_required=true.
RESULT=$(curl -sf -X POST https://api.shadowai.example.com/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"..."}')
# {"mfa_required":true,"mfa_token":"<short-lived-token>"}

MFA_TOKEN=$(echo "${RESULT}" | jq -r .mfa_token)

# 2. Submit TOTP code.
TOKEN=$(curl -sf -X POST https://api.shadowai.example.com/api/auth/mfa/verify \
  -H 'Content-Type: application/json' \
  -d "{\"mfa_token\":\"${MFA_TOKEN}\",\"code\":\"$(get-totp)\"}" | jq -r .token)
```

### Disable MFA (admin only)

```bash
curl -X DELETE https://api.shadowai.example.com/api/auth/mfa \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

---

## Audit Trail

All break-glass and MFA events are written to admin_event_logs:

| Action                    | Trigger                        |
|---------------------------|-------------------------------|
| `break_glass_login_success` | Successful break-glass login |
| `break_glass_login_failed`  | Failed attempt or rate-limited |
| `mfa_verified`             | TOTP code correct            |
| `mfa_failed`               | Wrong TOTP code or expired token |
| `mfa_challenge_required`   | MFA setup initiated          |
| `mfa_disabled`             | Admin disabled own MFA       |

Query break-glass events:
```bash
curl -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  'https://api.shadowai.example.com/api/admin-events?action=break_glass_login_success'
```

---

## Rate Limits

Break-glass is rate-limited to **3 attempts per 15 minutes** per instance.
If the limit is exceeded, wait 15 minutes or restart the pod.

In multi-instance deployments, each pod maintains its own counter (no cross-pod
coordination). This means the effective limit is `3 × pod_count` attempts
per window — acceptable since break-glass is for emergency use only.

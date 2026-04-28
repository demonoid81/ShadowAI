# ShadowAI Production Runbook — Master Index

This document is the entry point for all production operational procedures.
Each section links to the detailed runbook for that area.

**New (GA1):** [`docs/production-hardening.md`](../production-hardening.md) — supported
operating envelope, mandatory secrets/alerts, SIEM/evidence/streaming sizing, known limits,
and pre-launch checklist.

---

## Quick Reference

| Situation | Runbook |
|-----------|---------|
| Production hardening / defaults | [production-hardening.md](../production-hardening.md) |
| Production go/no-go validation | [production-validation.md](production-validation.md) |
| Streaming incremental rollout | [streaming-production-proof.md](streaming-production-proof.md) |
| Deploy / rollback | [deploy-rollback.md](deploy-rollback.md) |
| Emergency admin access | [break-glass.md](break-glass.md) |
| OIDC/IdP MFA not confirming | [oidc-idp-mfa.md](oidc-idp-mfa.md) |
| Audit chain break detected | [deploy-rollback.md#chain-break](deploy-rollback.md#audit-chain-break) |
| SIEM delivery failing | [deploy-rollback.md#siem-failure](deploy-rollback.md#siem-failure) |
| SA_v2 embedder degraded | [deploy-rollback.md#semantic-v2-degraded](deploy-rollback.md#semantic-v2-degraded) |
| Evidence export / WORM / Object Lock | [evidence-export-runbook.md](../evidence-export-runbook.md) |
| Quarterly compliance evidence collection | [evidence-collection.md](evidence-collection.md) |
| Access review (SOC2.3) | [access-review.md](access-review.md) |

---

## 1. Infrastructure Setup

### First-time deploy

```bash
# 1. Create namespace + secrets (see secret-matrix.md).
kubectl create namespace shadowai
kubectl create secret generic shadowai-secrets --namespace shadowai \
  --from-literal=databaseUrl='...' \
  --from-literal=jwtSecret='...' \
  --from-literal=redisUrl='...'

# 2. Run migrations (init container runs automatically on Helm install).
# Manual pre-check:
migrate --dir backend/migrations --enterprise-dir backend/migrations-enterprise

# 3. Install chart.
helm upgrade --install shadowai ./deploy/helm/shadowai \
  -f deploy/helm/shadowai/values-prod.yaml \
  --namespace shadowai \
  --set image.tag=$IMAGE_TAG \
  --set existingSecret=shadowai-secrets \
  --wait --timeout 10m
```

Reference: [deploy-rollback.md](deploy-rollback.md)  
Checklist: [deploy/helm/shadowai/docs/deploy-checklist.md](../../deploy/helm/shadowai/docs/deploy-checklist.md)  
Secrets: [deploy/helm/shadowai/docs/secret-matrix.md](../../deploy/helm/shadowai/docs/secret-matrix.md)
Go/no-go validation: [production-validation.md](production-validation.md)

---

## 2. Authentication

### Local admin (password + MFA)

| Situation | Action |
|-----------|--------|
| Admin forgot TOTP | Delete TOTP: `DELETE /api/auth/mfa` (authenticated). Or: use break-glass to access, disable MFA |
| TOTP device lost | Use break-glass emergency access |
| All admin passwords forgotten | Use break-glass, then reset passwords |

Break-glass: [break-glass.md](break-glass.md)

### OIDC / IdP

| Situation | Action |
|-----------|--------|
| Admin OIDC login fails with `admin_mfa_required` | Check what AMR/ACR the IdP sends (see audit event). Update `OIDC_MFA_AMR_VALUES` |
| All OIDC logins fail | Check `OIDC_ISSUER_URL` is reachable. Run: `curl $OIDC_ISSUER_URL/.well-known/openid-configuration` |
| OIDC discovery times out at startup | Check `OIDC_DISCOVERY_TIMEOUT` (default 10s). Increase or fix IdP connectivity |

IdP MFA setup: [oidc-idp-mfa.md](oidc-idp-mfa.md)

### SCIM

| Situation | Action |
|-----------|--------|
| SCIM provisioning returns 401 | Verify `SCIM_BEARER_TOKEN` matches what IdP sends |
| Deprovisioned user can still log in | Check `is_active` in DB. `token_version` should have bumped on deactivation |
| User reactivated unexpectedly | Check if IdP sent PUT without `active` field (full-replace defaults to active=true) |

---

## 3. Governance

### Policy management

```bash
# Get current policy.
curl -H "Authorization: Bearer $ADMIN_TOKEN" /api/governance/policy

# Update to context_scoped.
curl -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  /api/governance/policy -d '{
    "mode": "context_scoped",
    "context_rules": [...]
  }'
```

| Mode | When to use |
|------|-------------|
| `disabled` | No enforcement (bootstrap / dev) |
| `allowlist_strict` | Global provider/model allowlist |
| `role_based` | Per-role allowlist (PR-G2) |
| `context_scoped` | Per-department+sensitivity (PR-G3) |

Department setup: users must have `department` set. Use `PUT /api/users/{id}` with `{"department":"finance"}`.

### Emergency provider/model block

Policy updates are write-through on the serving replica and distributed to other
replicas through Redis pub/sub. The cache invalidation is scoped to the changed
`org_id`; unrelated org policies remain cached.

Emergency procedure:

1. Remove the provider/model from `/api/governance/policy` or add an explicit
   empty `rules` entry for the affected `context_scoped` rule.
2. Send a test request from a different pod or through the load balancer.
3. Confirm the request is denied before upstream call.
4. Check `shadowai_governance_cache_invalidations_total` increases on other
   replicas.
5. Check `shadowai_governance_cache_invalidation_publish_errors_total == 0`.

If publish errors are non-zero, assume some replicas may converge only through
TTL fallback. Restart pods or temporarily route traffic to a verified replica
for urgent incidents.

### LLM provider vendor-risk

Governance policy is the runtime enforcement of provider approval, not the
approval process itself. Before adding a provider/model to governance:

1. Complete `docs/compliance/templates/llm-provider-assessment-template.md`.
2. Add or update the row in `docs/compliance/templates/approved-llm-provider-register.csv`.
3. Confirm status is `approved` or `conditional` for the requested
   department/sensitivity.
4. Update `/api/governance/policy`.
5. Capture the admin event and sample allow/deny evidence.

Use `docs/compliance/llm-provider-vendor-risk.md` for the full process.

---

## 4. Evidence & Audit Chain (WORM)

### Chain verification

```bash
# Quick check.
audit-verify --anchor-only --table all --verbose

# Full W2 chain + anchors.
audit-verify --include-anchors --table all --verbose

# Offline bundle (no DB required).
audit-verify --bundle /path/to/evidence_bundle.zip --verbose
```

### Export evidence bundle

```bash
# Global export. Tenant export uses --org-id <uuid> instead.
audit-export-evidence \
  --output /tmp/evidence_$(date +%Y%m%d) \
  --global \
  --pubkey-file /etc/shadowai/anchor-pubkey.b64
```

Production deployments should normally use the scheduled `evidence-export`
CronJob from the Helm chart. It verifies the bundle before retaining it on PVC
or uploading it to S3/Object Lock storage.

### Chain break response

1. **Do not restart or redeploy until investigated.**
2. Run `audit-verify --table all --verbose` and save output.
3. Check `admin_event_logs` for recent DB access.
4. Engage security team.

---

## 5. SIEM

| Metric | Alert threshold | Action |
|--------|----------------|--------|
| `shadowai_siem_queue_depth` | > 800 for 5 min | Check SIEM endpoint reachability |
| `shadowai_siem_dropped_total` | Any | SIEM too slow; increase queue or fix endpoint |
| `shadowai_siem_retry_total{outcome=fail_all}` | Any | SIEM permanently failing; check endpoint |

Admin events continue writing to DB even when SIEM is down — no data loss.

---

## 6. Firewall

### Semantic V2 degradation

```bash
# Check fail-open rate (> 5% = degraded).
promtool query instant \
  'rate(shadowai_semantic_v2_inspect_total{result="fail_open"}[10m]) / 
   rate(shadowai_semantic_v2_inspect_total[10m])'

# Temporarily disable SA_v2.
kubectl set env deployment/shadowai FIREWALL_SA_V2_ENABLED=false
```

Promotion from shadow-only to enforce requires the F8.1 checklist in
[semantic-v2-promotion.md](semantic-v2-promotion.md): corpus verification,
`firewall-bench --with-embeddings`, reviewed `would_block` samples, and enabled
Prometheus alerts.

### Streaming mode

| Setting | Notes |
|---------|-------|
| `STREAMING_MODE=buffered` | Safe default. Full firewall coverage. |
| `STREAMING_MODE=shadow` | Buffered truth + shadow compare. Review mismatch rate before promoting. |
| `STREAMING_MODE=incremental` | Requires `STREAMING_ALLOW_INCREMENTAL_IN_PROD=true`. Soft budget only. |

Promote to incremental only when `shadowai_streaming_shadow_mismatch_total / compare_total < 1%`.

---

## 7. Observability

### Prometheus alerts → action mapping

| Alert | Severity | First action |
|-------|----------|-------------|
| `ShadowAIDown` | critical | Check pod logs: `kubectl logs -l app=shadowai --tail=100` |
| `ShadowAIReadinessFailure` | critical | Check `GET /api/ready` for which dependency is down |
| `AuditVerifyJobFailed` | critical | Run `audit-verify --verbose` manually; engage security if chain break |
| `SIEMBatchDeliveryFailing` | critical | Check SIEM endpoint connectivity |
| `SemanticV2FailOpenHigh` | warning | Check embedding service; disable SA_v2 temporarily |
| `SemanticV2WouldBlockHigh` | info | Review shadow-only samples before enforcement |
| `StreamingShadowMismatchHigh` | warning | Do NOT promote to incremental; investigate root cause |

Full alert runbooks: [deploy-rollback.md](deploy-rollback.md)

---

## 8. Scheduled Operations

### Daily audit-verify CronJob (if enabled)

```bash
# Enable in Helm.
helm upgrade shadowai ./deploy/helm/shadowai \
  --set auditVerifyCron.enabled=true \
  --set auditVerifyCron.chainSecret=true \  # if AUDIT_CHAIN_SECRET is configured
  --set auditVerifyCron.schedule="0 3 * * *"

# Check last run.
kubectl get jobs -l app.kubernetes.io/component=audit-verify -n shadowai
```

### Secret rotation schedule

| Secret | Recommended rotation | Reference |
|--------|---------------------|-----------|
| `jwtSecret` | Every 90 days | Coordinates with token TTL |
| `breakGlassSecretHash` | After every use (mandatory) + every 30 days | [break-glass.md](break-glass.md) |
| `scimBearerToken` | Every 90 days; coordinate with IdP | Secret matrix |
| `anchorSigningKey` | Annual; keep old public key for historical verify | WORM evidence |

---

## 9. Emergency Contacts

Fill in before production launch:

| Role | Contact |
|------|---------|
| On-call engineer | |
| Security team | |
| Database admin | |
| IdP/OIDC admin | |
| immudb operator | |

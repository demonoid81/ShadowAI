# ShadowAI Production Hardening Guide — GA1

**Version:** GA1 · **Date:** 2026-04-26

This document defines the supported operating envelope, recommended Helm production profile,
mandatory secrets and alerts, and known limits for a medium enterprise ShadowAI deployment.
It is the single reference for production-readiness validation before go-live.

Related: [`docs/runbooks/production.md`](runbooks/production.md) · [`docs/evidence-export-runbook.md`](evidence-export-runbook.md) · [`deploy/helm/shadowai/values-prod.yaml`](../deploy/helm/shadowai/values-prod.yaml)
· [`docs/runbooks/production-validation.md`](runbooks/production-validation.md)

---

## 1. Supported Operating Envelope

> **Note:** Numbers below are **design targets and operational recommendations**, not
> measured benchmark results. No load test has been run against this codebase. Label
> anything unverified as "target" when communicating with customers.

| Dimension | Target / Recommendation | Notes |
|-----------|------------------------|-------|
| Concurrent LLM proxy requests | ≤ 500 req/s per replica | Budget, governance and audit chain are the bottleneck; no profiling done |
| Audit chain write throughput | ~200 inserts/s per table (advisory lock serialized) | pg_advisory_xact_lock serializes per-table chain writes |
| SIEM async queue saturation | 1 000 events (default); burst beyond this triggers drop_oldest | Tune SIEM_QUEUE_SIZE for high-throughput deployments |
| Evidence export bundle size | Up to ~5 GB per global export (PVC) | Larger deployments should use S3 storage mode |
| Legal hold count | No hard limit; hot path is single index lookup on target_user_id | |
| Tenant count (org_id) | Tested with per-org isolation; no hard limit | Governance cache is per org; Redis invalidation propagates policy updates |
| Replicas | 3 – 10 (HPA) | Multi-replica: governance cache is in-process per replica with Redis pub/sub invalidation and TTL fallback |
| Kubernetes version | ≥ 1.27 | CronJob, PDB, PrometheusRule CRD required |
| PostgreSQL version | ≥ 14 | pg_advisory_xact_lock, partial unique indexes |

### Multi-replica governance invalidation

The governance policy cache (`CachingRepository`) writes through on same-replica
`UpsertPolicy` and publishes a Redis invalidation event for other replicas.
Other replicas drop only the affected `org_id` cache entry; the next request
reloads from PostgreSQL without waiting for the 60 s TTL fallback.

If Redis pub/sub delivery is unavailable, the policy still converges through the
TTL fallback. Operators should alert on
`shadowai_governance_cache_invalidation_publish_errors_total` because emergency
provider/model blocks may otherwise take up to the fallback window to reach all
replicas.

---

## 2. Mandatory Secrets

All secrets are read from a Kubernetes Secret referenced by `existingSecret` in `values.yaml`.
The following secrets are **required** for a production deployment. Missing any of these will
cause the application to refuse startup (`ValidateStartupConfig` exits with code 2).

| Secret key | Env var | Minimum entropy | Purpose |
|------------|---------|-----------------|---------|
| `databaseUrl` | `DATABASE_URL` | Connection string | PostgreSQL connection |
| `jwtSecret` | `JWT_SECRET` | 32+ chars | Session token signing |
| `auditChainSecret` | `AUDIT_CHAIN_SECRET` | 32+ chars | WORM HMAC chain (W2) |
| `legalHoldTokenSecret` | `LEGAL_HOLD_TOKEN_SECRET` | 32+ chars | Case-ref HMAC token (L1.2) |
| *(optional)* `siemBearerToken` | `SIEM_BEARER_TOKEN` | Bearer token | SIEM HTTP auth if required |
| *(optional)* `oidcClientSecret` | `OIDC_CLIENT_SECRET` | — | OIDC authorization code flow |
| *(optional)* `scimBearerToken` | `SCIM_BEARER_TOKEN` | 32+ chars | SCIM provisioning endpoint |
| *(optional)* `s3AccessKeyID` + `s3SecretAccessKey` | — | — | S3 evidence storage (O4.2) |
| *(optional)* `anchorPubKey` | — | 32 bytes base64 | Ed25519 anchor verification (W4.1) |
| *(optional)* `byokVaultToken` | `BYOK_VAULT_TOKEN` | Vault token policy-scoped to transit encrypt/decrypt | BYOK2 audit payload encryption when `BYOK_ENABLED=true` |

**Never** put these in `values.yaml` or `values-prod.yaml`. Use:
```bash
kubectl create secret generic shadowai-secrets --namespace shadowai \
  --from-literal=databaseUrl='postgres://...' \
  --from-literal=jwtSecret='...' \
  --from-literal=auditChainSecret='...' \
  --from-literal=legalHoldTokenSecret='...'
```

---

## 3. Mandatory Alerts

The following Prometheus alerts are considered mandatory for production. All are defined in
`deploy/helm/shadowai/templates/prometheusrule.yaml` when `evidenceExport.alerts.enabled: true`.

| Alert | Severity | Trigger | Response |
|-------|----------|---------|---------|
| `EvidenceExportJobFailed` | critical | CronJob exit != 0 | Check logs: chain/verify failure, disk full, DB down |
| `EvidenceExportJobMissing` | warning | CronJob not scheduled for 48h | Check CronJob suspension, controller logs |
| `EvidenceAuditReportJobFailed` | warning | Retention audit report failed | Check Object Lock violations or S3 config |
| `EvidenceAuditReportJobMissing` | warning | Audit report not run for 7 days | Check CronJob suspension |

**Additional alerts to configure in your alerting stack** (not yet in PrometheusRule):

| Metric | Recommended alert | Notes |
|--------|-------------------|-------|
| `shadowai_siem_dropped_total > 0` | warning | SIEM queue full; increase SIEM_QUEUE_SIZE or check SIEM delivery |
| `shadowai_siem_fail_total rate(5m)` | warning | SIEM delivery failures |
| `shadowai_governance_cache_reload_errors_total rate(5m) > 0` | warning | DB connectivity issue for governance |
| `shadowai_streaming_midstream_block_total` | info | Streaming firewall blocks; review content patterns |
| `shadowai_streaming_midstream_sanitize_total` | info | Streaming sanitize events; review if unexpected |

---

## 4. SIEM Sizing

| Parameter | Env var | Default | Recommended prod | Notes |
|-----------|---------|---------|-----------------|-------|
| Queue size | `SIEM_QUEUE_SIZE` | 1 000 | 5 000 – 10 000 | Burst buffer; increase for high-traffic deployments |
| Batch size | `SIEM_BATCH_SIZE` | 50 | 100 – 200 | Events per HTTP POST; increase if SIEM supports large payloads |
| Flush interval | `SIEM_FLUSH_INTERVAL` | 5s | 5s – 10s | Max latency between batches |
| Max retries | `SIEM_MAX_RETRIES` | 3 | 5 | Retry budget per batch; increase for unreliable SIEM |
| Drop policy | `SIEM_DROP_POLICY` | `drop_oldest` | `drop_oldest` | Drop oldest on queue full; `drop_newest` for audit completeness of recent events |
| Request timeout | `SIEM_TIMEOUT` | 3s | 5s | Increase for high-latency SIEM endpoints |

**Sizing formula (approximate)**:
- 1 audit event ≈ 500 B JSON
- 10 000-event queue ≈ 5 MB RAM overhead (acceptable)
- At 200 req/s → 200 events/s → queue drains in 50 s if SIEM delivery is interrupted

**Set in ConfigMap** (not secrets):
```yaml
config:
  SIEM_ENABLED: "true"
  SIEM_ENDPOINT: "https://siem.yourcompany.com/ingest"
  SIEM_QUEUE_SIZE: "5000"
  SIEM_BATCH_SIZE: "100"
  SIEM_FLUSH_INTERVAL: "5s"
  SIEM_MAX_RETRIES: "5"
  SIEM_DROP_POLICY: "drop_oldest"
```

---

## 5. Evidence / WORM Sizing

### Storage backend selection

| Scenario | Recommendation |
|---------|----------------|
| Single-tenant, < 1 GB/month audit volume | `storage: pvc`, 20 Gi |
| Multi-tenant or > 1 GB/month | `storage: s3` with Object Lock |
| Compliance with WORM immutability requirement | `storage: s3` + Object Lock **required** |
| Air-gap / on-premise | `storage: pvc` with manual backup |

### Object Lock prerequisites

S3 Object Lock requires the bucket to be created with Object Lock enabled **at creation time**.
This is an ops/Terraform responsibility. See [evidence-export-runbook.md §2](evidence-export-runbook.md)
for bucket creation commands.

When using Object Lock:
```yaml
evidenceExport:
  storage: s3
  s3:
    objectLock:
      enabled: true
      mode: "COMPLIANCE"       # COMPLIANCE = immutable even by root
      retentionDays: 90
```

### Retention audit report (O4.4)

The weekly retention audit report (`evidenceAuditReport`) is strongly recommended:
```yaml
evidenceAuditReport:
  enabled: true
  schedule: "0 8 * * 1"   # Monday 08:00 UTC
  requireLock: true
  minRetentionDays: 90
  format: json
```
Exit 1 from this CronJob triggers `EvidenceAuditReportJobFailed` alert.

### Key rotation (W7)

- **AUDIT_CHAIN_SECRET** rotation: use `--chain-keyring` with `audit-verify`. Document the
  rotation epoch in the on-call log. Old rows verified with old secret; new rows with new.
- **Ed25519 signing key**: pass new key_id + public key to anchor scheduler. Build a signing
  keyring JSON and pass `--signing-keyring` to `audit-verify`.
- **Restore drill**: run quarterly using `audit-verify --restore-drill --table all`
  with either `--pubkey-file` or `--signing-keyring` so the signature tier is
  verified, not silently skipped.

---

## 6. Streaming Safety Profile

### Production gate

`STREAMING_MODE: "buffered"` is the safe production default. Incremental streaming
(real-time passthrough) requires an explicit opt-in:

```yaml
config:
  STREAMING_MODE: "buffered"           # default: safe, no gate required
  # STREAMING_ALLOW_INCREMENTAL_IN_PROD: "true"  # explicit opt-in; see below
```

**Before enabling incremental streaming in production**, verify all F7.7 promotion criteria
(documented in `backend/internal/proxy/handler_streaming_incremental.go`):

1. Error budget: `streaming_emit_fail_total` + `streaming_decoder_fatal_total` rate < 0.1% for 30 days
2. Fallback rate: `streaming_fallback_total{reason="unsupported_provider"}` ≈ 0
3. Sanitize correctness: `shadowai_streaming_midstream_sanitize_total` reviewed in shadow mode for 30 days
4. Bytes-identity: `TestRoundTrip_BytesIdentity` passes on the version being promoted
5. Provider coverage: all production providers have full `EmitSanitized` (tier-1 providers: OpenAI-compatible, Anthropic, Gemini, Ollama)
6. Security team sign-off on sanitize audit samples

### CM+judge fallback

Content Moderation + LLM judge inspectors force buffered fallback regardless of
`STREAMING_MODE`. This is by design (CM+judge needs full response before verdict).
If you enable `FIREWALL_JUDGE_ENABLED: "true"`, all streaming traffic falls back to buffered.

### Shadow mode (semantic_v2)

`FIREWALL_SA_V2_ENABLED: "false"` is the safe default. To promote semantic_v2:
validate the corpus with `firewall-corpus-verify`, run
`firewall-bench --with-embeddings`, then enable `FIREWALL_SA_V2_ENABLED=true`
with `FIREWALL_SA_V2_SHADOW_ONLY=true`. Do not set shadow-only to false until
the review window in `docs/runbooks/semantic-v2-promotion.md` is complete.

Required promotion signals:
- `shadowai_semantic_v2_inspect_total{result="fail_open"}` near zero
- `shadowai_semantic_v2_inspect_total{result="would_block"}` samples reviewed
- Helm `firewallAlerts.enabled=true` or equivalent Prometheus alerts installed

---

## 7. Tenant Isolation Operational Notes

### Default org behavior

All users require an `org_id`. Legacy users without `org_id` are treated as belonging
to the default org (`00000000-0000-0000-0000-000000000001`). This is set by migration seeds.

### SCIM provisioning

SCIM token provisioning is per-org:
```bash
kubectl exec -it <pod> -- curl -X POST http://localhost:8080/scim/v2/Tokens \
  -H "Authorization: Bearer <global-admin-jwt>" \
  -d '{"org_id": "<uuid>", "description": "SCIM provisioner"}'
```
Token is returned once. Store in IdP SCIM connector immediately.

### Global admin scope

`global_admin` role can read cross-tenant chain fields and manage holds, but:
- Cannot decrypt BYOK-protected tenant payload by role alone; decrypt requires
  access to the configured KMS/Vault Transit key
- Cannot approve holds for which they are the creator (4-eyes)
- Cannot approve release of a hold they requested (L5 4-eyes for release)
- Admin events from global_admin operations are tagged with `source_org_id`/`target_org_id`

### Governance cache and multi-tenant

Per-org governance policy is cached independently. `UpsertPolicy` on org A
publishes an invalidation for org A only and does not invalidate org B's cache.
Redis pub/sub is the primary cross-replica synchronization mechanism; TTL is the
fallback convergence path.

---

## 8. Recommended Helm Production Profile Summary

See `deploy/helm/shadowai/values-prod.yaml` for the full file. Key settings:

```yaml
# Availability
replicaCount: 3
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 65

# Security — set streaming to buffered (safe default)
config:
  APP_ENV: "production"
  AUDIT_PAYLOAD_MODE: "redacted"
  STREAMING_MODE: "buffered"
  FIREWALL_ENABLED: "true"

# Evidence export — PVC default; switch to s3 for compliance storage
evidenceExport:
  enabled: true
  chainSecret: true
  alerts:
    enabled: true
    severity: critical

# Retention audit report — enabled weekly
evidenceAuditReport:
  enabled: true

# SIEM — configure in config section (not here; endpoint is operator-specific)
# evidenceAuditReport alerts enabled automatically when evidenceAuditReport.enabled=true
```

**Operator-specific items that must be customized** (not defaultable):
- `OIDC_ISSUER_URL` + `OIDC_CLIENT_ID` — customer IdP
- `SIEM_ENDPOINT` — customer SIEM
- S3 bucket name, region, credentials — customer AWS/MinIO
- `image.tag` — set at deploy time from CI
- `ingress.hosts` — customer domain

---

## 9. Known Limits Before GA

| Limit | Description | Mitigation / Future work |
|-------|-------------|--------------------------|
| Streaming incremental: cross-chunk PII sanitize | F7.8 fail-closes unsafe sanitize verdicts when a sensitive match spans already emitted chunks. It does not retroactively rewrite bytes that were already sent | Keep proof-window audit review mandatory; monitor `stream_blocked_midflight` / `shadowai_streaming_midstream_block_total` for cross-chunk spikes before removing the prod gate |
| Evidence export: O(n) bundle size with org count | Global export grows with audit log volume; no streaming export | Use per-tenant export mode for large deployments |
| Legal hold selector privacy | Portable evidence bundles include `selector_manifest.jsonl` for query-scope auditor explainability. The v1 bundle exports selector JSON plus hash; it does not yet offer a hash-only or BYOK-encrypted selector export mode | Use tenant-scoped exports for least disclosure; use WORM `legal_hold_events` selector hash for integrity; defer hash-only/BYOK selector bundles to L8.2/BYOK |
| BYOK: partial v1 | BYOK2 encrypts `audit_logs.request_body` and `audit_logs.response_body` for new writes through Vault Transit envelopes. BYOK2.1 adds an explicit `audit-byok-sweep` CLI for legacy rows; legal-hold selectors are not encrypted yet | Enable `BYOK_ENABLED=true` with `BYOK_PROVIDER=vault_transit`; run `audit-byok-sweep --dry-run` then `audit-byok-sweep --limit N` during a maintenance window; keep tenant-scoped exports for least disclosure; plan v2 DEK epochs for full BYOK lifecycle |
| Evidence witness independence is configuration-dependent | W8 supports additional independent anchor sinks, but a deployment can still run with only one configured sink | Configure `AUDIT_ANCHOR_ADDITIONAL_SINKS` for regulated deployments and alert on degraded sink writes |
| Restore drill evidence is operator-owned | `audit-verify --restore-drill` automates verification, but the product does not automatically attest that the drill was executed and archived | Run quarterly, store output in the compliance evidence package, and link it from the incident/compliance log |
| No formal pen test | SEC1 provides a scoped LLM security validation package, but no external assessor has executed it yet | Schedule external validation before regulated-industry go-live; use `docs/security/llm-red-team-validation-package.md` |
| No SAML support | OIDC + SCIM are the supported enterprise identity path. IAM1 documents SAML as customer-dependent, not implemented | Use `docs/security/saml-enterprise-identity-gap-assessment.md` in security reviews; implement SAML only after target customer IdP metadata and claims contract are available |

BYOK legacy sweep example:

```bash
export BYOK_ENABLED=true
export BYOK_PROVIDER=vault_transit
export BYOK_VAULT_ADDR=https://vault.example.com
export BYOK_VAULT_TOKEN=...
export BYOK_VAULT_KEY_NAME=shadowai-audit-payload

audit-byok-sweep --database-url "$DATABASE_URL" --dry-run --limit 1000
audit-byok-sweep --database-url "$DATABASE_URL" --limit 1000
```

Important: the sweep updates payload columns only. WORM canonical hashes remain valid
because request/response bodies are not canonical fields; the sweep does not add
proof-of-content-existence for historical plaintext payloads.

---

## 10. Pre-Launch Checklist

Run this before each production deployment:

```bash
# 1. Helm validate
make helm-validate

# 2. PROD1 preflight validation
shadowai-prod-validate \
  --chart ./deploy/helm/shadowai \
  --values ./deploy/helm/shadowai/values-prod.yaml \
  --release shadowai \
  --namespace shadowai \
  --existing-secret shadowai-secrets \
  --image-tag "$IMAGE_TAG" \
  --format json \
  --output prod1-preflight.json

# 3. Enterprise tests
go test -tags enterprise ./... -count=1

# 4. Smoke tests (requires Postgres + Redis)
go test -tags 'enterprise smoke' ./smoke/... -count=1

# 5. Evidence chain verify (against restored DB if doing restore drill)
audit-verify --restore-drill --table all --pubkey-file ./anchor-pubkey.b64 --verbose

# 6. Retention audit report (against evidence S3 bucket)
audit-evidence-report \
  --bucket <prod-bucket> \
  --require-lock \
  --min-retention-days 90 \
  --format json

# 7. Confirm mandatory secrets exist in cluster
kubectl get secret shadowai-secrets -n <namespace> \
  -o jsonpath='{.data}' | jq 'keys'
```

Expected output for step 4: all `OK`. Any `FAIL` requires investigation before deployment.

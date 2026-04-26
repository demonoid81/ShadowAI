# Evidence Export & Restore Drill — Operator Runbook

**PR-O4.1 + O4.2 + O4.3** · Last updated: 2026-04-26

---

## Overview

The automated evidence pipeline covers O4.1 PVC storage, O4.2 S3-compatible
storage, and O4.3 optional S3 Object Lock retention:

```
CronJob (nightly)
  → audit-export-evidence --global | --org-id    (local temp or PVC)
  → audit-verify --bundle                         (offline Merkle proof verification)
  → [storage=s3] evidence-upload → S3/MinIO       (upload only after successful verify)
  → [storage=pvc] retain on PVC, cleanup old
  → exit 0 or fail Job → EvidenceExportJobFailed alert
```

Storage backends:
- **`storage: pvc`** (O4.1 default) — bundles stored on a PVC at `/exports`.
- **`storage: s3`** (O4.2/O4.3) — bundles staged on an explicit `emptyDir`, verified,
  uploaded to S3/MinIO, optionally protected with Object Lock, then deleted from local disk.

Evidence bundles are cryptographic compliance artifacts: signed Merkle anchors,
chain inventory (or Merkle proofs for tenant bundles), and SHA256 file manifests.
Once created and verified they can be handed to auditors without live DB access.

---

## 1. Checking the Latest Bundle

### Kubernetes

```bash
# List recent Jobs
kubectl -n <namespace> get jobs -l app.kubernetes.io/component=evidence-export

# Check the last run's logs
kubectl -n <namespace> logs job/<job-name> -c evidence-export

# List bundles on the PVC (via temporary pod)
kubectl -n <namespace> run tmpshell --image=busybox --rm -it \
  --overrides='{"spec":{"volumes":[{"name":"e","persistentVolumeClaim":{"claimName":"shadowai-evidence-exports"}}],"containers":[{"name":"tmpshell","image":"busybox","volumeMounts":[{"name":"e","mountPath":"/exports"}]}]}}' \
  -- ls -lh /exports/
```

### Find the most recent verified bundle

```bash
# Inside the tmpshell pod above:
ls -lt /exports/ | head -5
# or for zipped bundles:
ls -lt /exports/*.zip | head -5
```

---

## 2. S3 Object Lock Prerequisites (O4.3)

Object Lock must be enabled **at bucket creation time** — it cannot be enabled on an existing
bucket. This is an ops/Terraform responsibility, not the application chart.

### AWS S3

```bash
# Create bucket with Object Lock enabled (versioning is automatically enabled).
aws s3api create-bucket \
  --bucket shadowai-compliance \
  --region us-east-1 \
  --object-lock-enabled-for-bucket

# Optional: set a bucket-level default retention (applied when PutObject omits retention headers).
# The per-object headers from evidence-upload override this default.
aws s3api put-object-lock-configuration \
  --bucket shadowai-compliance \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 90
      }
    }
  }'

# Verify Object Lock is active:
aws s3api get-object-lock-configuration --bucket shadowai-compliance
```

### MinIO

```bash
# Create bucket with object locking enabled:
mc mb --with-lock minio/shadowai-compliance

# Set default retention (optional):
mc retention set --default COMPLIANCE 90d minio/shadowai-compliance

# Verify:
mc retention info minio/shadowai-compliance
```

### Helm configuration

```yaml
evidenceExport:
  storage: s3
  s3:
    bucket: shadowai-compliance
    sse: "AES256"          # use "none" for MinIO/custom S3 targets that reject SSE-S3
    objectLock:
      enabled: true
      mode: "COMPLIANCE"     # or GOVERNANCE
      retentionDays: 90
      legalHold: ""          # "ON" | "OFF" | "" (omit header)
```

Object Lock is valid only with `storage: s3`. If it is enabled with `storage: pvc`,
Helm must fail render; PVC storage is not WORM-grade immutable storage.

### Verifying retention on a specific object

```bash
# AWS S3
aws s3api head-object \
  --bucket shadowai-compliance \
  --key shadowai/evidence/2026/04/26/global-20260426-020001.zip \
  --query '{Mode:ObjectLockMode,RetainUntil:ObjectLockRetainUntilDate,LegalHold:ObjectLockLegalHoldStatus}'

# Expected output (COMPLIANCE, 90-day window):
# {
#   "Mode": "COMPLIANCE",
#   "RetainUntil": "2026-07-25T02:00:01+00:00",
#   "LegalHold": null
# }

# MinIO
mc stat --json minio/shadowai-compliance/shadowai/evidence/2026/04/26/global-20260426-020001.zip \
  | jq '{mode: .metadata["X-Amz-Object-Lock-Mode"], until: .metadata["X-Amz-Object-Lock-Retain-Until-Date"]}'
```

### Behaviour when bucket is not Object Lock-enabled

If `objectLock.enabled: true` but the bucket was created without `--object-lock-enabled-for-bucket`,
AWS returns HTTP 400 / `InvalidRequest`. `evidence-upload` exits 1, the CronJob fails, and the
`EvidenceExportJobFailed` alert fires. **Do not disable Object Lock in Helm to work around this —
fix the bucket instead.**

AWS S3 requires a checksum on `PutObject` requests that set Object Lock retention.
`evidence-upload` satisfies this by setting `ChecksumAlgorithm=CRC32` explicitly when
`--object-lock-mode` is passed; the SDK computes and sends `x-amz-checksum-crc32` inline
as the body streams (single read, no buffering). AWS SDK v2 also adds `x-amz-checksum-crc32`
by default on all PutObject requests regardless of Object Lock — the explicit
`x-amz-sdk-checksum-algorithm: CRC32` header signals the intentional election.
A checksum-related upload rejection indicates an SDK version mismatch, not a reason to
disable retention.

---

## 3. Retrieving a Bundle from S3 / MinIO (storage=s3)

```bash
# AWS S3
aws s3 cp \
  s3://shadowai-compliance/shadowai/evidence/2026/04/26/global-20260426-020001.zip \
  ./evidence-bundle-20260426.zip

# MinIO via mc CLI
mc cp \
  minio/shadowai-compliance/shadowai/evidence/2026/04/26/global-20260426-020001.zip \
  ./evidence-bundle-20260426.zip

# MinIO via aws CLI with custom endpoint
AWS_ACCESS_KEY_ID=<key> AWS_SECRET_ACCESS_KEY=<secret> \
  aws s3 cp \
    s3://shadowai-compliance/shadowai/evidence/2026/04/26/global-20260426-020001.zip \
    . \
    --endpoint-url http://minio:9000

# List all bundles for a given day
aws s3 ls s3://shadowai-compliance/shadowai/evidence/2026/04/26/
```

### S3 key format

```
<prefix>/<YYYY>/<MM>/<DD>/<bundle-name>.zip
shadowai/evidence/2026/04/26/global-20260426-020001.zip
shadowai/evidence/2026/04/26/tenant-<org_id>-20260426-020001.zip
```

Then unzip and verify:

```bash
unzip global-20260426-020001.zip
audit-verify --bundle ./global-20260426-020001 --verbose
```

---

## 4. Offline Bundle Verification

```bash
# Copy bundle from PVC to local machine
kubectl -n <namespace> cp \
  tmpshell:/exports/global-20260426-020001 \
  ./evidence-bundle-20260426

# Verify offline (no DATABASE_URL required)
audit-verify --bundle ./evidence-bundle-20260426 --verbose
# For tenant bundles (T3/W6 Merkle proofs):
# audit-verify --bundle ./tenant-bundle-<org_id>-20260426 --verbose
```

Expected output for a clean bundle:
```
bundle file_integrity          OK     checked=5 fails=0
bundle sigs                    OK     total=3 unsigned=0 no_pubkey=0 fails=0
bundle anchor_range audit_logs OK     anchors=3 gaps=0
bundle inventory    audit_logs OK     rows=1200 gaps=0
bundle count        audit_logs OK     anchors=3 mismatches=0
```

For tenant bundles:
```
tenant bundle proofs            OK     checked=47 failed=0
tenant bundle sigs              OK     failed=0
```

---

## 5. Handing Bundle to an Auditor

```bash
# Verify first, then zip for transfer
audit-verify --bundle ./evidence-bundle-20260426 --verbose
zip -r evidence-bundle-20260426.zip ./evidence-bundle-20260426/

# SHA256 checksum for chain of custody
sha256sum evidence-bundle-20260426.zip
```

The bundle contains `README.txt` with offline verification instructions.
The auditor only needs the bundle directory and (optionally) `public_key.b64`
for Ed25519 anchor signature verification.

---

## 6. W7 Key Epoch Model and Rotation

### 6.1 Key epoch model

ShadowAI uses two independent key types for evidence integrity:

| Key type | Used for | Epoch model |
|----------|----------|-------------|
| `AUDIT_CHAIN_SECRET` | HMAC chain (W2) per-row tamper detection | Range-based: seq_no epochs |
| Ed25519 signing key | Anchor manifest signatures (W4.1) | ID-based: `pubkey_id` per anchor |

After rotation, **old evidence is verified with old keys, new evidence with new keys**.
No DB schema change is required — epoch is determined at verify time.

### 6.2 Signing key rotation (Ed25519)

**Writer side** (anchor scheduler): rotate by passing a new key pair with a new `pubkey_id`:
```bash
# Generate new key pair
openssl genpkey -algorithm ed25519 -out new-signing.pem
openssl pkey -in new-signing.pem -pubout -out new-signing-pub.pem

# Pass new key to anchor scheduler via env:
ANCHOR_SIGNING_KEY_ID=ed25519-2026-Q3
ANCHOR_SIGNING_PRIVATE_KEY=<base64 of new private key>
```

**Verifier side**: build a signing keyring file `signing-keyring.json`:
```json
{
  "keys": {
    "ed25519-2026-Q1": "base64pubkey-v1...",
    "ed25519-2026-Q2": "base64pubkey-v2...",
    "ed25519-2026-Q3": "base64pubkey-v3..."
  },
  "legacy_key": "base64pubkey-pre-W4.1..."
}
```

Verify anchors across all epochs:
```bash
audit-verify \
  --table all \
  --verify-signatures \
  --signing-keyring ./signing-keyring.json \
  --verbose
```

Rules:
- `keys`: known pubkey_id → public key (checked fail-closed: unknown key_id = failure)
- `legacy_key`: used for anchors with empty `pubkey_id` (pre-W4.1 compatibility)
- Extra keys in the keyring (not referenced by anchors) are not errors

### 6.3 Chain secret rotation (AUDIT_CHAIN_SECRET)

**Writer side**: change `AUDIT_CHAIN_SECRET` in deployment. New rows use new secret; old rows were sealed with old secret.

**Verifier side**: build a chain keyring file `chain-keyring.json`:
```json
{
  "epochs": [
    {"from_seq_no": 0, "to_seq_no": 12499, "secret_base64": "base64-secret-v1..."},
    {"from_seq_no": 12500, "to_seq_no": -1, "secret_base64": "base64-secret-v2..."}
  ]
}
```

`to_seq_no: -1` means "no upper bound" (current epoch). `from_seq_no` of each epoch must
not overlap with the previous.

Verify chain across epochs:
```bash
audit-verify \
  --table audit_logs \
  --chain-keyring ./chain-keyring.json \
  --verbose
```

Without `--chain-keyring`, `AUDIT_CHAIN_SECRET` env var is used as a single-epoch keyring
(backward-compatible with all existing deployments).

---

## 7. W8 Second Independent Anchor Sink

### 7.1 Design

W8 adds optional multi-sink anchor publication. The same Ed25519-signed manifest is
written to ALL configured sinks — no re-signing with different content. The primary
`audit_chain_anchors` row stores the primary sink info; a new table
`audit_chain_anchor_sinks` records per-additional-sink results.

Partial failure is explicit: if sink B fails, `sink_ok=false` with `error_msg` in
`audit_chain_anchor_sinks`. No silent all-ok.

### 7.2 Recommended independent sink pairs

| Primary (default) | Secondary (W8) | Independence |
|------------------|----------------|--------------|
| `file://` (local PVC) | `immudb://` (external append-only) | DBA cannot forge without both |
| `file://` | Second `file://` on separate PVC/host | Operational resilience |
| `immudb://` | `file://` on S3-backed object store | Cross-environment witness |

The point is that compromise of ONE storage backend does not destroy the audit trail.
An auditor can detect tampering by cross-checking the two independently stored manifests.

### 7.3 Configuration

```go
// In enterprise_wire.go, extend the anchor scheduler:
scheduler := chain.NewAnchorScheduler(chainRepo, primaryFileSink, interval, tables).
    WithSigning(privKey, pubKeyID, pubKey).
    WithAdditionalSinks(
        chain.NewFileSink("/exports/anchors-secondary.ndjson"),
        // or immudb sink, or any AnchorSink implementation
    )
```

The additional sinks receive the **same** manifest bytes as the primary sink.
Write order does not affect the signed manifest.

### 7.4 Monitoring partial failures

```sql
-- Find anchors with failed additional sinks:
SELECT a.table_name, a.anchor_seq_lo, a.anchor_seq_hi, s.sink_name, s.error_msg
FROM audit_chain_anchors a
JOIN audit_chain_anchor_sinks s ON s.anchor_id = a.id
WHERE s.sink_ok = false
ORDER BY a.created_at DESC
LIMIT 20;
```

Each failure is also logged:
```
anchor: PARTIAL SINK FAILURE table=audit_logs seq=[1,100] sink=file:// err=...
anchor scheduler: DEGRADED EVIDENCE POSTURE: additional sink(s) failed: [file://]
```

Add a Prometheus alert on log pattern or query if SIEM has structured log search.

### 7.5 Verification with additional sinks

```bash
# List recorded additional sinks for anchors:
# (requires DB access — no CLI flag yet in W8; SQL query above)

# Manually verify an additional file sink:
audit-verify --anchor-sink-path /exports/anchors-secondary.ndjson \
  --table audit_logs --include-anchors --verbose
```

The verifier cross-checks the additional sink against the primary DB anchor rows.
A mismatch (different Merkle root in secondary vs DB) indicates tampering of either the
DB row or the external sink file.

### 7.6 Backward compatibility

- Anchors written before W8 have no rows in `audit_chain_anchor_sinks`.
- `audit-verify` treats empty additional sinks as single-sink (legacy) mode.
- Existing verification commands work unchanged.

---

## 8. Restore Drill

A restore drill verifies that WORM evidence survives a DB restore and that
anchors/bundles remain consistent with the restored data.

### 7.1 Prerequisites

- PG backup (pg_dump or managed snapshot)
- Evidence bundle from same point in time
- `AUDIT_CHAIN_SECRET` (stored separately, not in DB backup)
- Optional: signing keyring file for multi-epoch key verification

### 7.2 Automated restore drill (W7)

The `--restore-drill` flag runs the full verification suite in a single command.
Use this in CI/CronJob pipelines and for quarterly drills.

```bash
# 1. Restore DB to a new instance
createdb shadowai_restore
pg_restore -d shadowai_restore backup.dump

export DATABASE_URL=postgres://user:pass@restore-host/shadowai_restore
export AUDIT_CHAIN_SECRET=<secret from vault>

# 2. Run automated restore drill (chain + anchors + signatures in sequence)
audit-verify \
  --restore-drill \
  --table all \
  --verbose

# With multi-epoch signing keyring:
audit-verify \
  --restore-drill \
  --table all \
  --signing-keyring ./signing-keyring.json \
  --verbose

# With chain secret rotation keyring:
audit-verify \
  --restore-drill \
  --table all \
  --chain-keyring ./chain-keyring.json \
  --signing-keyring ./signing-keyring.json \
  --verbose

# 3. Verify offline bundle
audit-verify --bundle ./evidence-bundle-20260426 --verbose

# 4. Cross-check row counts
psql $DATABASE_URL -c \
  "SELECT table_name, COUNT(*) FROM audit_chain_anchors GROUP BY table_name"
```

Exit codes:
- `0` — all verifications passed
- `1` — one or more verification failures (chain break, anchor mismatch, bad signature)
- `2` — configuration error (missing env vars, invalid keyring file)

### 7.3 Manual drill steps (if automated flow unavailable)

```bash
# Step 1: chain verification
audit-verify --table all --verbose

# Step 2: anchor verification
audit-verify --anchor-only --table all --verbose

# Step 3: signature verification
audit-verify --verify-signatures --table all \
  --signing-keyring ./signing-keyring.json --verbose

# Step 4: offline bundle
audit-verify --bundle ./evidence-bundle-20260426 --verbose
```

### 7.4 Restore Drill Frequency

Recommended: quarterly. Required before SOC2 audit windows.
Document each drill in the incident log with timestamp, operator, and results.

---

## 9. Alert Response

### EvidenceExportJobFailed

```bash
# 1. Check logs
kubectl -n <namespace> logs job/<failed-job-name>

# Common causes:
# - DATABASE_URL unreachable → check DB connectivity
# - audit-verify --bundle exit 1 → Merkle verification failure (investigate tamper)
# - Disk full on PVC → increase PVC size or reduce retentionDays
# - AUDIT_CHAIN_SECRET missing → check K8s secret
# - S3 upload failed → check S3 credentials, bucket policy, endpoint, path-style mode
# - Object Lock upload failed → verify bucket was created with Object Lock enabled
# - Object Lock checksum error → verify uploader sends Content-MD5 or checksum algorithm

# 2. Re-run manually (does not affect CronJob schedule)
kubectl -n <namespace> create job evidence-export-manual \
  --from=cronjob/shadowai-evidence-export
```

### EvidenceExportJobMissing

```bash
# Check if CronJob is suspended
kubectl -n <namespace> get cronjob shadowai-evidence-export

# If suspended, unsuspend:
kubectl -n <namespace> patch cronjob shadowai-evidence-export \
  -p '{"spec":{"suspend":false}}'
```

### Bundle Verify Failure (suspected tampering)

> **Note:** `EvidenceBundleVerifyFailed` was removed as a separate alert — it used the
> same `kube_job_status_failed` expression as `EvidenceExportJobFailed`, making it
> indistinguishable from DB outages, disk full, or config errors.
> `EvidenceExportJobFailed` is the canonical alert for any CronJob exit != 0.

When logs show `audit-verify --bundle` returned non-zero (lines starting with
`bundle … FAIL` or `tenant bundle … FAIL`), treat it as a potential tamper incident:

**Immediate actions:**
1. Do NOT delete the failed bundle.
2. Copy it to a secure location before any remediation.
3. Run `audit-verify --bundle <dir> --verbose` locally and capture full output.
4. Escalate to security team and compliance officer.
5. Run `audit-verify --include-anchors --table all` against live DB to check DB integrity.

**Distinguishing verify failure from other causes in the Job log:**

```bash
kubectl -n <namespace> logs job/<failed-job-name> | grep -E "FAIL|error|ERROR"
# Verify failure → lines like: "bundle file_integrity FAIL checked=5 fails=2"
# DB connectivity → lines like: "dial tcp: connection refused"
# Disk full       → lines like: "write /exports/...: no space left on device"
```

---

## 10. Evidence Retention Audit Report (O4.4)

`audit-evidence-report` gives operators and auditors a point-in-time view of the
retention posture of every evidence bundle in S3 — without database access.

### Manual run

```bash
# Human-readable table — operator use
audit-evidence-report \
  --bucket shadowai-compliance \
  --prefix shadowai/evidence \
  --require-lock \
  --min-retention-days 90 \
  --format table

# Machine-readable JSON — CI / auditor archive
audit-evidence-report \
  --bucket shadowai-compliance \
  --prefix shadowai/evidence \
  --require-lock \
  --min-retention-days 90 \
  --format json \
  --output /tmp/retention-report-$(date +%Y%m%d).json

# Scoped to a quarter (2026-Q1)
audit-evidence-report \
  --bucket shadowai-compliance \
  --after 2026-01-01 \
  --before 2026-03-31 \
  --require-lock \
  --min-retention-days 90 \
  --format json

# MinIO with custom endpoint
audit-evidence-report \
  --bucket shadowai-compliance \
  --endpoint http://minio:9000 \
  --force-path-style \
  --require-lock \
  --min-retention-days 90 \
  --format table
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All bundles compliant (or no policy flags set) |
| 1 | One or more violations — `EvidenceAuditReportJobFailed` alert fires when running as CronJob |
| 2 | S3 access / configuration error — same alert |

### Violation types

| Violation | Cause |
|-----------|-------|
| `missing_object_lock` | Bundle has no Object Lock mode (fired when `--require-lock`) |
| `missing_retention` | `retain_until` is absent and `--min-retention-days > 0` — no WORM protection |
| `lock_expired(since=YYYY-MM-DD)` | `retain_until` is in the past |
| `retention_too_short(retain_until=...,need_days=N)` | `retain_until < now + N days` |
| `manifest_read_error(...)` | Bundle zip is corrupt, truncated, or missing `bundle_manifest.json` (only with `--read-manifest`) |

### Providing retention coverage to an auditor

```bash
# 1. Generate a quarterly report
audit-evidence-report \
  --bucket shadowai-compliance \
  --after 2026-01-01 --before 2026-03-31 \
  --require-lock --min-retention-days 90 \
  --format json \
  --output evidence-retention-Q1-2026.json

# 2. Verify the report itself (no violations = exit 0)
jq '.violation_count' evidence-retention-Q1-2026.json
# Expected: 0

# 3. For each bundle verify individual retention:
jq '.bundles[] | {key, lock_mode, retain_until, compliant}' \
  evidence-retention-Q1-2026.json

# 4. SHA256 for chain of custody
sha256sum evidence-retention-Q1-2026.json
```

The JSON report contains `generated_at`, `bucket`, `prefix`, policy parameters,
per-bundle `lock_mode` and `retain_until`, and `compliant`/`violations` fields —
sufficient for SOC2 and ISO27001 evidence archives.

### Helm CronJob (weekly)

```yaml
evidenceAuditReport:
  enabled: true
  schedule: "0 8 * * 1"   # Mondays 08:00 UTC
  requireLock: true
  minRetentionDays: 90
  format: json
  # bucket/region/secretName default to evidenceExport.s3.* when empty
```

---

## 11. Helm Configuration Reference

```yaml
evidenceExport:
  enabled: true
  schedule: "0 2 * * *"     # nightly at 02:00 UTC
  mode: global               # or: tenants
  orgIDs: []                 # required when mode=tenants
  retentionDays: 90          # delete bundles older than 90 days
  storage: pvc               # pvc | s3
  pvc:
    size: 20Gi
  s3:
    bucket: ""               # required when storage=s3
    prefix: "shadowai/evidence"
    region: "us-east-1"
    endpoint: ""             # custom endpoint for MinIO/GCS/etc.
    forcePathStyle: false    # true for most MinIO installs
    stagingSize: "2Gi"       # emptyDir limit for local staging
    sse: "AES256"            # AES256 | none
    secretName: ""           # defaults to existingSecret
    accessKeyIDKey: s3AccessKeyID
    secretAccessKeyKey: s3SecretAccessKey
    objectLock:
      enabled: false
      mode: "COMPLIANCE"     # GOVERNANCE | COMPLIANCE
      retentionDays: 90
      legalHold: ""          # ON | OFF | "" (omit header)
  chainSecret: true          # include AUDIT_CHAIN_SECRET for W2 chain verify
  zip: true                  # archive bundles
  pubKeyFile: ""             # optional: path to Ed25519 public key
  alerts:
    enabled: true
    severity: critical
    missingAfterSeconds: 172800  # 48h
```

---

## 12. Prometheus Queries

```promql
# Jobs that failed in the last 24h
kube_job_status_failed{
  namespace="shadowai",
  job_name=~"shadowai.*evidence-export.*"
} > 0

# Hours since last successful evidence export
(time() - kube_cronjob_status_last_schedule_time{
  namespace="shadowai",
  cronjob="shadowai-evidence-export"
}) / 3600

# PVC usage (if monitoring PVC metrics)
kubelet_volume_stats_used_bytes{
  persistentvolumeclaim="shadowai-evidence-exports"
} / kubelet_volume_stats_capacity_bytes{
  persistentvolumeclaim="shadowai-evidence-exports"
}
```

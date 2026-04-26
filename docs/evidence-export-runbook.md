# Evidence Export & Restore Drill — Operator Runbook

**PR-O4.1 + O4.2 + O4.3** · Last updated: 2026-04-26

---

## Overview

The automated evidence pipeline (O4.1: PVC, O4.2: S3-compatible):

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
- **`storage: s3`** (O4.2) — bundles staged locally, verified, uploaded to S3/MinIO, then deleted from local disk.

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
    sse: "AES256"
    objectLock:
      enabled: true
      mode: "COMPLIANCE"     # or GOVERNANCE
      retentionDays: 90
      legalHold: ""          # "ON" | "OFF" | "" (omit header)
```

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

## 6. Restore Drill

A restore drill verifies that WORM evidence survives a DB restore and that
anchors/bundles remain consistent with the restored data.

### 4.1 Prerequisites

- PG backup (pg_dump or managed snapshot)
- Evidence bundle from same point in time
- `AUDIT_CHAIN_SECRET` (stored separately, not in DB backup)

### 4.2 Steps

```bash
# 1. Restore DB to a new instance
createdb shadowai_restore
pg_restore -d shadowai_restore backup.dump

export DATABASE_URL=postgres://user:pass@restore-host/shadowai_restore
export AUDIT_CHAIN_SECRET=<secret from vault>

# 2. Run chain verification against restored DB
audit-verify --include-anchors --table all --verbose

# 3. Compare Merkle roots: DB-computed roots must match bundle anchors
#    (Run from the restored DB context)
audit-verify --bundle ./evidence-bundle-20260426 --verbose

# 4. Cross-check row counts
psql $DATABASE_URL -c \
  "SELECT table_name, COUNT(*) FROM audit_chain_anchors GROUP BY table_name"

# 5. Verify no gaps in chain coverage
audit-verify --table audit_logs --verbose
audit-verify --table admin_event_logs --verbose
```

Expected: all verifications pass. Any discrepancy indicates tampering or an
incomplete backup.

### 4.3 Restore Drill Frequency

Recommended: quarterly. Required before SOC2 audit windows.
Document each drill in the incident log with timestamp, operator, and results.

---

## 7. Alert Response

### EvidenceExportJobFailed

```bash
# 1. Check logs
kubectl -n <namespace> logs job/<failed-job-name>

# Common causes:
# - DATABASE_URL unreachable → check DB connectivity
# - audit-verify --bundle exit 1 → Merkle verification failure (investigate tamper)
# - Disk full on PVC → increase PVC size or reduce retentionDays
# - AUDIT_CHAIN_SECRET missing → check K8s secret

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

### EvidenceBundleVerifyFailed

This is the most critical alert. It means `audit-verify --bundle` returned non-zero,
which indicates:
- Tampered bundle files (SHA256 mismatch)
- Forged Merkle proofs (root mismatch)
- Invalid anchor signatures (key mismatch or canonical format change)

**Immediate actions:**
1. Do NOT delete the failed bundle.
2. Copy it to a secure location.
3. Run `audit-verify --bundle <dir> --verbose` and capture full output.
4. Escalate to security team and compliance officer.
5. Run `audit-verify --include-anchors --table all` against live DB to check DB integrity.

---

## 8. Helm Configuration Reference

```yaml
evidenceExport:
  enabled: true
  schedule: "0 2 * * *"     # nightly at 02:00 UTC
  mode: global               # or: tenants
  orgIDs: []                 # required when mode=tenants
  retentionDays: 90          # delete bundles older than 90 days
  storage: pvc               # pvc only for O4.1; s3 in O4.2
  pvc:
    size: 20Gi
  chainSecret: true          # include AUDIT_CHAIN_SECRET for W2 chain verify
  zip: true                  # archive bundles
  pubKeyFile: ""             # optional: path to Ed25519 public key
  alerts:
    enabled: true
    severity: critical
    missingAfterSeconds: 172800  # 48h
```

---

## 9. Prometheus Queries

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

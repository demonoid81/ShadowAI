# Quarterly Compliance Evidence Collection Runbook (SOC2.1 + SOC2.2)

This runbook describes how to generate a quarterly compliance evidence package using
`audit-collect-evidence`. The package is designed to be passed to an external auditor
or security reviewer without requiring live system access for static artifacts.

---

## Overview

`audit-collect-evidence` collects and packages:

| Artifact | Auto-collected | Requires |
|---------|---------------|---------|
| SOC2/ISO control mapping snapshot | Yes (if `--controls-doc` provided) | Path to mapping doc |
| S3 retention posture report | Yes | `--bucket` + S3 access |
| WORM chain + anchor verification | Yes | `DATABASE_URL` + `AUDIT_CHAIN_SECRET` |
| Access review checklist (template) | Yes | — |
| Incident/alert review checklist (template) | Yes | — |
| CI/release checklist (template) | Yes | — |
| `not_collected.json` | Always | — |

Templates require operator completion. Runtime artifacts (retention, chain verify) require
live system credentials. The `not_collected.json` file documents what could not be
collected automatically, with explicit reasons and instructions.

---

## Required Credentials

| Purpose | Where | Required for |
|---------|-------|--------------|
| S3 access | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` env | Retention report |
| DB access | `DATABASE_URL` env | Chain verification |
| Chain secret | `AUDIT_CHAIN_SECRET` env | Chain verification |
| EC2 metadata disabled | `AWS_EC2_METADATA_DISABLED=true` | Prevent timeout in non-EC2 env |

Secrets must **never** appear in the generated package. The CLI reads them from the
environment and uses them to run sub-commands; they are not written to any output file.

---

## Quarterly Collection Flow

### Step 1: Determine the audit period

```bash
PERIOD_FROM="2026-01-01"
PERIOD_TO="2026-03-31"
OUTPUT="./evidence-Q1-2026"
```

### Step 2: Set environment variables

```bash
export DATABASE_URL="postgres://user:pass@host/shadowai_prod"
export AUDIT_CHAIN_SECRET="<from vault>"
export AWS_ACCESS_KEY_ID="<access key>"
export AWS_SECRET_ACCESS_KEY="<secret key>"
export AWS_EC2_METADATA_DISABLED="true"
```

### Step 3: Run audit-collect-evidence

```bash
# Minimal run (generates templates + not_collected for runtime checks):
audit-collect-evidence \
  --from "$PERIOD_FROM" \
  --to   "$PERIOD_TO" \
  --output "$OUTPUT" \
  --format dir

# Full run (with SOC2 mapping, S3 retention report, chain verify):
audit-collect-evidence \
  --from "$PERIOD_FROM" \
  --to   "$PERIOD_TO" \
  --output "$OUTPUT" \
  --format dir \
  --controls-doc ./docs/compliance/soc2-iso-control-mapping.md \
  --bucket shadowai-compliance \
  --region us-east-1

# Output as zip for transfer to auditor:
audit-collect-evidence \
  --from "$PERIOD_FROM" \
  --to   "$PERIOD_TO" \
  --output "evidence-Q1-2026.zip" \
  --format zip \
  --controls-doc ./docs/compliance/soc2-iso-control-mapping.md \
  --bucket shadowai-compliance \
  --allow-incomplete
```

### Step 4: Review not_collected.json

```bash
cat ./evidence-Q1-2026/evidence/not_collected.json
```

For each `not_collected` item, either:
1. Provide the required credential and re-run to collect it, OR
2. Run the indicated command manually and add the output to the package directory

### Step 5: Complete the checklist templates

Open each file in `checklists/`:
- `access-review-checklist.md` — fill in admin accounts, SCIM review, legal holds
- `incident-alert-review-checklist.md` — fill in alerts fired, SIEM status, chain verify
- `ci-release-checklist.md` — fill in releases deployed, security-relevant changes

### Step 6: Compute final SHA256

After completing the templates, recompute hashes for the entire package:

```bash
# If you modified files after initial generation, update hashes manually:
find ./evidence-Q1-2026 -type f -not -name manifest.json | sort | \
  xargs sha256sum > ./evidence-Q1-2026/file-checksums.txt
```

Note: the `manifest.json` contains `file_sha256` computed at generation time.
If templates are modified after generation, the hashes in `manifest.json` will differ
from the final files. This is expected and acceptable — the manifest shows what was
auto-generated; manual completions are clearly identified by file content.

### Step 7: Transfer to auditor

```bash
# Zip the final directory:
zip -r evidence-Q1-2026-final.zip ./evidence-Q1-2026/

# SHA256 for chain of custody:
sha256sum evidence-Q1-2026-final.zip
```

Provide the auditor with:
1. The zip file
2. The SHA256 checksum (separately, e.g. email or signed document)
3. Instructions for offline verification (see below)

---

## Output Package Structure

```
evidence-Q1-2026/
├── manifest.json                          # Package manifest with SHA256 of all files
├── controls/
│   └── soc2-iso-control-mapping.md        # SOC2/ISO control mapping snapshot
├── evidence/
│   ├── retention-report.json             # S3 Object Lock retention posture (if S3 available)
│   ├── chain-verify-summary.json         # WORM chain+anchor verification output (if DB available)
│   └── not_collected.json                # Controls that could not be auto-collected
└── checklists/
    ├── access-review-checklist.md        # Operator completes: admin review, SCIM, legal holds
    ├── incident-alert-review-checklist.md # Operator completes: alerts, SIEM, incidents
    └── ci-release-checklist.md           # Operator completes: releases, change management
```

### manifest.json format

```json
{
  "schema_version": "1",
  "generated_at": "2026-04-26T08:00:00Z",
  "generator": "audit-collect-evidence",
  "build_commit": "a40a150...",
  "period": {"from": "2026-01-01", "to": "2026-03-31"},
  "controls": [
    {
      "id": "soc2_control_mapping",
      "description": "SOC 2 / ISO 27001 control mapping snapshot",
      "status": "collected",
      "file": "controls/soc2-iso-control-mapping.md"
    },
    {
      "id": "retention_posture",
      "status": "not_collected",
      "live_check_required": true,
      "reason": "--bucket not provided; run: audit-evidence-report ..."
    }
  ],
  "file_sha256": {
    "controls/soc2-iso-control-mapping.md": "...",
    "checklists/access-review-checklist.md": "..."
  }
}
```

**Control statuses:**
- `collected` — artifact included in package, file hash in manifest
- `template` — template file generated; operator must fill in
- `not_collected` — could not auto-collect; see `reason` field

---

## How the Auditor Verifies the Package

1. **Verify manifest SHA256**: `sha256sum evidence-Q1-2026.zip` matches the provided checksum
2. **Check manifest.json**: Confirm period, generator, build_commit
3. **Verify file hashes**: For each `collected` control, verify `file_sha256` against actual files
4. **Review SOC2 mapping**: `controls/soc2-iso-control-mapping.md` — control objectives and gaps
5. **Review retention report**: `evidence/retention-report.json` — Object Lock compliance
6. **Review chain verify**: `evidence/chain-verify-summary.json` — WORM integrity result
7. **Review completed checklists**: Operator-signed checklists in `checklists/`
8. **Check not_collected.json**: Confirm understanding of what was not auto-collected

The auditor does **not** need:
- Database access
- S3 access
- AUDIT_CHAIN_SECRET
- Any application credentials

The chain verify summary and retention report are pre-computed outputs included in
the package. Integrity of the chain is proven by `chain-verify-summary.json`
(which contains `audit-verify --restore-drill` output).

---

## What Is NOT Included

The following items are intentionally excluded from the evidence package:

| Excluded | Reason |
|---------|--------|
| Raw audit log rows | Contains potential PII; use chain-verify summary instead |
| Evidence bundle ZIP files | Too large; reference bundle storage location instead |
| Application secrets (JWT, chain secret) | Never included; used only to run sub-commands |
| Kubernetes pod logs | Risk of PII and large volume; check SIEM for structured events |
| Database dumps | Not required for audit; chain verify proves integrity |
| User PII (emails, names) | Audit evidence does not require PII to prove control operation |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All controls collected (or --allow-incomplete set) |
| 1 | One or more controls not_collected (use --allow-incomplete to proceed) |
| 2 | Configuration or runtime error (bad flags, can't write output) |

---

## Troubleshooting

| Problem | Resolution |
|---------|-----------|
| `audit-evidence-report not found in PATH` | Run `make build-cli` or add binary to PATH |
| `audit-verify not found in PATH` | Same as above |
| S3 access denied | Check `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` |
| Chain verify fails (exit 1) | Chain integrity failure — investigate before sending to auditor |
| Chain verify config error (exit 2) | Check `DATABASE_URL` and `AUDIT_CHAIN_SECRET` |
| `--controls-doc` not found | Pass explicit path: `--controls-doc ./docs/compliance/soc2-iso-control-mapping.md` |

---

## Scheduled Collection (SOC2.2 — Helm CronJob)

### Overview

SOC2.2 adds a Helm-managed CronJob (`evidenceCollection`) that:
1. Calculates the audit period automatically (previous month, previous quarter, or explicit)
2. Runs `audit-collect-evidence` to build the package
3. Uploads the zip to S3 using `evidence-upload` (with optional Object Lock)
4. Fires `EvidenceCollectionJobFailed` or `EvidenceCollectionJobMissing` alerts

### Helm configuration

```yaml
evidenceCollection:
  enabled: true
  schedule: "0 4 1 1,4,7,10 *"   # quarterly: 1st of Jan/Apr/Jul/Oct at 04:00 UTC
  periodMode: "previous_quarter"   # or: previous_month | explicit
  allowIncomplete: false            # fail Job if any controls are not_collected

  s3:
    bucket: shadowai-compliance
    prefix: shadowai/evidence-collection
    region: us-east-1
    sse: "AES256"
    objectLock:
      enabled: true
      mode: "COMPLIANCE"
      retentionDays: 2555   # 7 years

  chainVerify:
    enabled: true    # pass DATABASE_URL + AUDIT_CHAIN_SECRET + anchorPubKey for restore-drill

  alerts:
    enabled: true
    severity: critical
    missingAfterSeconds: 2678400   # 31 days
```

### Period calculation

| `periodMode` | Run month | FROM | TO |
|-------------|-----------|------|-----|
| `previous_quarter` | January (Q1) | Oct 1 prior year | Dec 31 prior year |
| `previous_quarter` | April (Q2) | Jan 1 this year | Mar 31 |
| `previous_quarter` | July (Q3) | Apr 1 | Jun 30 |
| `previous_quarter` | October (Q4) | Jul 1 | Sep 30 |
| `previous_month` | February | Jan 1 | Jan 31 |
| `previous_month` | March | Feb 1 | Feb 28/29 |
| `explicit` | any | `periodFrom` | `periodTo` |

**First run after deploy**: If there is no evidence for the computed period (e.g., no
bundles in S3 for that quarter), `audit-collect-evidence` will include the retention
report as empty/not_collected. This is expected for first runs.

### S3 bucket prerequisites

The S3 bucket must be pre-created. If Object Lock is enabled:
```bash
# AWS S3
aws s3api create-bucket \
  --bucket shadowai-compliance \
  --object-lock-enabled-for-bucket

# Optional default retention
aws s3api put-object-lock-configuration \
  --bucket shadowai-compliance \
  --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Years":7}}}'
```

**Helm does not create the bucket.** This is an ops/Terraform responsibility.

### Retrieving an evidence package from S3

```bash
# List available packages
aws s3 ls s3://shadowai-compliance/shadowai/evidence-collection/

# Download a specific quarterly package
aws s3 cp \
  s3://shadowai-compliance/shadowai/evidence-collection/2026/01/evidence-collection-2025-10-01-to-2025-12-31.zip \
  ./evidence-Q4-2025.zip

# Verify download
sha256sum evidence-Q4-2025.zip
unzip evidence-Q4-2025.zip
cat manifest.json | jq '.controls[] | {id, status}'
```

### Failure handling

| Alert | Meaning | Action |
|-------|---------|--------|
| `EvidenceCollectionJobFailed` | Job exited non-zero | Check `kubectl logs job/<name>`; look for chain verify failures or S3 upload errors |
| `EvidenceCollectionJobMissing` | CronJob not run in 31 days | Check CronJob suspension; verify schedule |

**S3 upload failure after successful collection**: Job exits non-zero. Package was
collected locally but NOT uploaded to S3. The staging emptyDir is ephemeral — package
is lost when Pod terminates. Re-run manually with explicit `--from`/`--to`.

**Incomplete package policy** (`allowIncomplete`):
- `false` (default): Job fails if any controls are not_collected. Audit team sees 0
  packages for this period. Strong signal that something is wrong.
- `true`: Job succeeds with incomplete package. Package is uploaded; `not_collected.json`
  documents gaps. Use when some controls are intentionally unavailable (e.g., no DB for
  chain verify in a specific environment).

### Manual re-run for a specific period

```bash
# Re-collect for Q4 2025 with chain verification
kubectl run evidence-regen --rm -it \
  --image=shadowai:<tag> \
  --env="AWS_ACCESS_KEY_ID=$(kubectl get secret shadowai-secrets -o jsonpath='{.data.s3AccessKeyID}' | base64 -d)" \
  --env="AWS_SECRET_ACCESS_KEY=$(kubectl get secret shadowai-secrets -o jsonpath='{.data.s3SecretAccessKey}' | base64 -d)" \
  --env="DATABASE_URL=$(kubectl get secret shadowai-secrets -o jsonpath='{.data.databaseUrl}' | base64 -d)" \
  --env="AUDIT_CHAIN_SECRET=$(kubectl get secret shadowai-secrets -o jsonpath='{.data.auditChainSecret}' | base64 -d)" \
  --command -- \
  /bin/sh -c '
    audit-collect-evidence \
      --from 2025-10-01 --to 2025-12-31 \
      --output /tmp/evidence-Q4-2025.zip --format zip \
      --bucket shadowai-compliance && \
    evidence-upload \
      --file /tmp/evidence-Q4-2025.zip \
      --bucket shadowai-compliance \
      --key shadowai/evidence-collection/2025/10/evidence-collection-2025-10-01-to-2025-12-31.zip \
      --region us-east-1 --sse AES256 --timeout 120
  '
```

---

## Related Documents

- [`docs/compliance/soc2-iso-control-mapping.md`](../compliance/soc2-iso-control-mapping.md) — control mapping
- [`docs/evidence-export-runbook.md`](../evidence-export-runbook.md) — evidence pipeline + Object Lock prerequisites
- [`docs/production-hardening.md`](../production-hardening.md) — mandatory secrets and alerts
- [`docs/runbooks/streaming-production-proof.md`](streaming-production-proof.md) — streaming rollout

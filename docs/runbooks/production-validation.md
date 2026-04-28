# ShadowAI Production Validation Runbook (PROD1)

This runbook describes the deployment-specific validation pack used before a
customer production go-live. It complements the generic hardening guide: the
hardening guide defines required posture, while this runbook records evidence
that the target environment actually satisfies it.

Related:
- [`docs/production-hardening.md`](../production-hardening.md)
- [`docs/runbooks/production.md`](production.md)
- [`docs/evidence-export-runbook.md`](../evidence-export-runbook.md)

---

## 1. What PROD1 Validates

`shadowai-prod-validate` runs only built-in checks. It does not read or print
secrets, and it does not execute arbitrary commands from a user-provided file.

| Check | Trigger flag | Tool / endpoint | Required when configured |
|-------|--------------|-----------------|--------------------------|
| Helm render | `--chart` | `helm template` | Yes |
| Kubernetes rollout | `--live` | `kubectl rollout status` | Yes |
| Liveness | `--base-url` | `GET /api/health` | Yes |
| Readiness | `--base-url` | `GET /api/ready` | Yes |
| Evidence bundle verify | `--evidence-bundle` | `audit-verify --bundle` | Yes |
| S3/Object Lock posture | `--bucket` | `audit-evidence-report` | Yes |

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | All configured required checks passed |
| `1` | At least one configured required check failed |
| `2` | Configuration error: bad flags, invalid URL, no checks configured, output write failure |

---

## 2. Inputs

The validation pack needs deployment coordinates, not raw secrets.

| Input | Example | Secret? |
|-------|---------|---------|
| Helm chart path | `./deploy/helm/shadowai` | No |
| Helm values file | `./deploy/helm/shadowai/values-prod.yaml` | No |
| Namespace / release | `shadowai` | No |
| Base URL | `https://shadowai.example.com` | No |
| Evidence bundle path | `/mnt/evidence/latest.zip` | No |
| S3 bucket / prefix | `shadowai-compliance`, `shadowai/evidence` | No |

The underlying commands may require credentials from the environment:

| Tool | Credentials source |
|------|--------------------|
| `kubectl` | Current kubeconfig / service account |
| `audit-evidence-report` | Standard AWS env or instance role |
| `audit-verify --bundle` | No DB or chain secret required for bundle mode |

Do not pass passwords, bearer tokens, JWTs or chain secrets as CLI flags.

Runtime prerequisites on the machine/container that runs `shadowai-prod-validate`:

| Enabled check | Required binary |
|---------------|-----------------|
| `--chart` | `helm` |
| `--live` | `kubectl` |
| `--evidence-bundle` | `audit-verify` |
| `--bucket` | `audit-evidence-report` |

---

## 3. Preflight Only

Use this before touching the cluster. It verifies Helm render with production
values and produces a JSON report that can be archived.

```bash
shadowai-prod-validate \
  --chart ./deploy/helm/shadowai \
  --values ./deploy/helm/shadowai/values-prod.yaml \
  --release shadowai \
  --namespace shadowai \
  --existing-secret shadowai-secrets \
  --image-tag "$IMAGE_TAG" \
  --format json \
  --output prod1-preflight.json
```

Expected result: exit `0` and `"overall": "pass"`.

---

## 4. Live Deployment Validation

Run after Helm deploy and before go-live traffic is enabled.

```bash
shadowai-prod-validate \
  --chart ./deploy/helm/shadowai \
  --values ./deploy/helm/shadowai/values-prod.yaml \
  --release shadowai \
  --namespace shadowai \
  --existing-secret shadowai-secrets \
  --image-tag "$IMAGE_TAG" \
  --live \
  --base-url "https://shadowai.example.com" \
  --format table
```

This verifies:

1. Helm still renders with the deployed values.
2. `deployment/shadowai` has rolled out in the target namespace.
3. `/api/health` returns `200`.
4. `/api/ready` returns `200`.

Any failure is a no-go until investigated.

---

## 5. Evidence Validation

Run after the evidence export CronJob has produced at least one bundle.

```bash
shadowai-prod-validate \
  --evidence-bundle /exports/evidence_bundle_latest.zip \
  --bucket shadowai-compliance \
  --prefix shadowai/evidence \
  --region us-east-1 \
  --require-object-lock \
  --min-retention-days 90 \
  --format json \
  --output prod1-evidence.json
```

For MinIO or custom S3-compatible storage:

```bash
shadowai-prod-validate \
  --evidence-bundle /exports/evidence_bundle_latest.zip \
  --bucket shadowai-compliance \
  --prefix shadowai/evidence \
  --endpoint http://minio.example.com:9000 \
  --force-path-style \
  --require-object-lock \
  --min-retention-days 90
```

Expected result:

- `evidence_bundle` passes: offline bundle verification works without DB access.
- `evidence_retention` passes: Object Lock and retention posture satisfy policy.

---

## 6. Full Go / No-Go Command

Use this as the final validation command for a production launch.

```bash
shadowai-prod-validate \
  --chart ./deploy/helm/shadowai \
  --values ./deploy/helm/shadowai/values-prod.yaml \
  --release shadowai \
  --namespace shadowai \
  --existing-secret shadowai-secrets \
  --image-tag "$IMAGE_TAG" \
  --live \
  --base-url "https://shadowai.example.com" \
  --evidence-bundle /exports/evidence_bundle_latest.zip \
  --bucket shadowai-compliance \
  --prefix shadowai/evidence \
  --region us-east-1 \
  --require-object-lock \
  --min-retention-days 90 \
  --format json \
  --output prod1-go-no-go.json
```

Decision rules:

| Result | Decision |
|--------|----------|
| Exit `0`, all checks pass | Go |
| Exit `1` | No-go; resolve failed checks first |
| Exit `2` | Validation invalid; fix command/config and rerun |

Archive:

- `prod1-preflight.json`
- `prod1-go-no-go.json`
- Helm release version and image digest
- Evidence bundle checksum
- Any incident/remediation notes

---

## 7. Troubleshooting

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| `helm_template` fails | Bad values, missing required chart value, invalid object lock config | Run `helm template` manually with the same flags |
| `kubectl_rollout` fails | Pods not ready, image pull error, migration/init failure | `kubectl describe pod`, check init container logs |
| `http_health` fails | Service/ingress not reachable | Check ingress DNS/TLS/service routing |
| `http_ready` fails | DB/Redis dependency not ready | Check `/api/ready` response body and backend logs |
| `evidence_bundle` fails | Bundle integrity/signature/range problem | Run `audit-verify --bundle <path> --verbose` |
| `evidence_retention` fails | S3 Object Lock missing or retention too short | Run `audit-evidence-report` directly and inspect violations |

---

## 8. Known Limitations

- The CLI validates what it can observe. It does not replace a formal pen test,
  SOC 2 audit, ISO certification, or customer-specific DR exercise.
- `kubectl_rollout` assumes the deployment name equals `--release`. If an
  installation customizes names, run the check manually and archive the output.
- The CLI does not test real LLM provider credentials. Use smoke tests and
  controlled proxy requests for provider-specific validation.
- The CLI does not include secrets in its output. Secret presence is validated
  indirectly through startup/readiness and the relevant underlying tools.

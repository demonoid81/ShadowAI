# ShadowAI Production Deploy Checklist

Run this checklist before every production deployment. Items marked **BLOCKING**
will cause runtime failures or security gaps if skipped.

---

## Pre-Deploy

### Infrastructure
- [ ] **BLOCKING**: Kubernetes cluster is accessible (`kubectl cluster-info`)
- [ ] **BLOCKING**: Postgres (>= 16) is running and reachable from the cluster
- [ ] **BLOCKING**: Redis (>= 7) is running and reachable from the cluster
- [ ] Container registry credentials are configured (`imagePullSecrets`)
- [ ] Namespace `shadowai` exists (`kubectl create namespace shadowai`)

### Secrets (create before install)
See `deploy/helm/shadowai/docs/secret-matrix.md` for the full list.

```bash
kubectl create secret generic shadowai-secrets \
  --namespace shadowai \
  --from-literal=databaseUrl='postgres://user:pass@host:5432/db?sslmode=require' \
  --from-literal=jwtSecret='<STRONG_RANDOM_32+CHARS>' \
  --from-literal=redisUrl='redis://:password@redis:6379/0'
```

- [ ] **BLOCKING**: `shadowai-secrets` secret exists in namespace
- [ ] `databaseUrl` points to a production Postgres (not localhost)
- [ ] `jwtSecret` is >= 32 chars and not a placeholder value
- [ ] `redisUrl` has authentication if Redis is exposed beyond localhost

### Image
- [ ] Image tag is a specific SHA or semver (not `latest` in prod)
- [ ] Image built with `-tags enterprise` for enterprise features
- [ ] Core or enterprise variant is intentional and documented

---

## Configuration Validation

```bash
# Validate Helm templates render cleanly.
helm template shadowai ./deploy/helm/shadowai \
  -f deploy/helm/shadowai/values-prod.yaml \
  --set existingSecret=shadowai-secrets \
  --set image.tag=$IMAGE_TAG \
  > /tmp/render-check.yaml && echo "✓"

# Lint the chart.
helm lint ./deploy/helm/shadowai \
  --set existingSecret=shadowai-secrets
```

- [ ] `helm template` renders without errors or warnings
- [ ] `helm lint` passes
- [ ] ConfigMap SCREAMING_SNAKE_CASE keys match app env vars (no camelCase)
- [ ] `APP_ENV=production` is set in ConfigMap config
- [ ] `AUDIT_RETENTION_DAYS` is non-zero OR `AUDIT_ALLOW_NO_RETENTION_IN_PROD=true`

### Enterprise feature gates (if enabled)
- [ ] `OIDC_ENABLED=true` → `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URL` are set and HTTPS
- [ ] `SIEM_ENABLED=true` → `SIEM_ENDPOINT` is HTTPS, `SIEM_BEARER_TOKEN` is set
- [ ] `SCIM_ENABLED=true` → `SCIM_BEARER_TOKEN` is set and strong
- [ ] `BREAK_GLASS_ENABLED=true` → `BREAK_GLASS_SECRET_HASH` is set
- [ ] `AUDIT_ANCHOR_SINK=immudb://` → immudb connection + signing key configured
- [ ] `FIREWALL_SA_V2_ENABLED=true` → embedding endpoint is non-localhost
- [ ] `evidenceExport.storage=s3` → S3 bucket, credentials, endpoint, and path-style setting are validated in staging
- [ ] `evidenceExport.s3.objectLock.enabled=true` → bucket was created with Object Lock enabled; do not enable this on an existing non-lock bucket
- [ ] `evidenceExport.s3.objectLock.enabled=true` → upload path has checksum support (`Content-MD5` or SDK checksum algorithm), otherwise AWS S3 rejects locked `PutObject`

---

## Database

### Migrations
```bash
# Verify migration count before deploy.
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM schema_migrations;"
# Expected: matches number of SQL files in migrations/ + migrations-enterprise/

# Run migrations (handled automatically by init container in Helm chart).
# Manual dry-run:
migrate --dir migrations --enterprise-dir migrations-enterprise
```

- [ ] **BLOCKING**: All pending migrations tested in staging first
- [ ] Migration is additive (no DROP TABLE, no NOT NULL without DEFAULT)
- [ ] Rollback path documented if migration is risky
- [ ] `schema_migrations` table count matches expected

---

## Deploy

```bash
helm upgrade --install shadowai ./deploy/helm/shadowai \
  -f deploy/helm/shadowai/values-prod.yaml \
  --namespace shadowai \
  --set image.repository=ghcr.io/shadowai/shadowai \
  --set image.tag=$IMAGE_TAG \
  --set existingSecret=shadowai-secrets \
  --timeout 10m \
  --wait
```

- [ ] `--wait` is used (waits for pods to be ready)
- [ ] Rolling update strategy: `maxUnavailable: 0` (zero-downtime)
- [ ] PodDisruptionBudget: `minAvailable: 2` in prod

---

## Post-Deploy Verification

```bash
# Liveness.
kubectl exec -n shadowai deploy/shadowai -- wget -qO- http://localhost:8080/api/health
# Expected: {"status":"ok"}

# Readiness.
kubectl exec -n shadowai deploy/shadowai -- wget -qO- http://localhost:8080/api/ready
# Expected: {"ready":true,"checks":{"db":{"ok":true},"redis":{"ok":true}}}

# External smoke check.
curl -sf https://api.shadowai.example.com/api/health
```

- [ ] **BLOCKING**: All pods `Running` and `Ready` (0/N is a failure)
- [ ] `/api/health` returns 200
- [ ] `/api/ready` returns 200 with `"ready":true`
- [ ] `/metrics` endpoint is accessible from Prometheus scraper
- [ ] No `ERROR` lines in recent pod logs (`kubectl logs -l app=shadowai --tail=50`)

### Functional smoke checks
- [ ] Admin login works (password or OIDC)
- [ ] API proxy endpoint responds (non-admin test user)
- [ ] Governance policy is active (`GET /api/governance/policy`)
- [ ] Audit logs are being written (`GET /api/audit/logs`)

---

## Rollback

If any post-deploy check fails:
```bash
helm rollback shadowai
kubectl rollout status deployment/shadowai -n shadowai
```

See `docs/runbooks/deploy-rollback.md` for detailed rollback procedures.

---

## Post-Deploy Cleanup

- [ ] Old deployment artifacts removed from registry (if any)
- [ ] Deploy recorded in incident tracker / change management system
- [ ] On-call engineer notified that deploy is complete
- [ ] Prometheus alerts checked (no new firing alerts in first 15 minutes)

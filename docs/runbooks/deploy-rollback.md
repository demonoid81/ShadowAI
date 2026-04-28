# ShadowAI Deploy / Rollback Runbook

## Prerequisites

```bash
kubectl config use-context <your-prod-cluster>
kubectl config set-context --current --namespace=shadowai
helm repo update   # if using remote Helm registry
```

---

## Standard Deploy

### 1. Build and push image

```bash
# Tag with git SHA for traceability.
export IMAGE_TAG=$(git rev-parse --short HEAD)
docker build -t shadowai:${IMAGE_TAG} ./backend
docker tag shadowai:${IMAGE_TAG} registry.example.com/shadowai:${IMAGE_TAG}
docker push registry.example.com/shadowai:${IMAGE_TAG}
```

### 2. Upgrade

```bash
helm upgrade shadowai ./deploy/helm/shadowai \
  -f deploy/helm/shadowai/values-prod.yaml \
  --set image.repository=registry.example.com/shadowai \
  --set image.tag=${IMAGE_TAG} \
  --timeout 10m \
  --wait          # wait until all pods are ready
```

The init container runs database migrations automatically before the new app
pods start. Zero-downtime: `maxUnavailable: 0` keeps old pods serving until
new ones pass readiness checks.

### 3. Verify

```bash
# Check rollout status.
kubectl rollout status deployment/shadowai

# Tail logs for errors.
kubectl logs -l app.kubernetes.io/name=shadowai --tail=50 -f

# Readiness probe.
kubectl exec -it deploy/shadowai -- wget -qO- http://localhost:8080/api/ready

# Smoke test.
curl -sf https://api.shadowai.example.com/api/health
```

---

## Rollback

### Fast rollback (to previous Helm revision)

```bash
# List history.
helm history shadowai --max 5

# Roll back one revision.
helm rollback shadowai

# Or to a specific revision.
helm rollback shadowai <REVISION_NUMBER>

# Wait for rollback to complete.
kubectl rollout status deployment/shadowai
```

> **Note:** Helm rollback only reverts the application config and image.
> Database schema migrations are NOT reverted — ensure your migrations are
> backward-compatible (additive only, no destructive changes in prod).

### Emergency rollback (kubectl)

```bash
kubectl rollout undo deployment/shadowai
kubectl rollout status deployment/shadowai
```

---

## Migration-Only Run

Run migrations without deploying a new app version (e.g. pre-seeding):

```bash
kubectl run migrate-job \
  --image=registry.example.com/shadowai:${IMAGE_TAG} \
  --restart=Never \
  --command -- migrate \
    --dir /migrations \
    --enterprise-dir /migrations-enterprise \
  --env="DATABASE_URL=$(kubectl get secret shadowai-secrets -o jsonpath='{.data.databaseUrl}' | base64 -d)"
```

---

## Canary Rollout

For high-risk changes, route a fraction of traffic to the new version:

```bash
# 1. Deploy new version with a separate Helm release named 'shadowai-canary'.
helm upgrade --install shadowai-canary ./deploy/helm/shadowai \
  -f deploy/helm/shadowai/values-prod.yaml \
  --set image.tag=${IMAGE_TAG} \
  --set replicaCount=1              # 1 canary pod alongside 3 stable
  --set podDisruptionBudget.enabled=false

# 2. Monitor canary metrics (5xx rate, P99 latency, firewall decisions).
# If clean after 30 minutes, proceed with full deploy.

# 3. Full deploy.
helm upgrade shadowai ./deploy/helm/shadowai \
  -f deploy/helm/shadowai/values-prod.yaml \
  --set image.tag=${IMAGE_TAG}

# 4. Remove canary.
helm uninstall shadowai-canary
```

---

## Common Failure Modes

### Instance Down

**Alert:** `ShadowAIDown`

```bash
kubectl get pods -l app.kubernetes.io/name=shadowai
kubectl describe pod <crashing-pod>
kubectl logs <crashing-pod> --previous
```

Common causes:
- OOMKilled → increase `resources.limits.memory`
- CrashLoopBackOff on startup → check config validation errors (`kubectl logs`)
- Image pull error → check registry credentials

### Readiness Failure

**Alert:** `ShadowAIReadinessFailure`

```bash
# Check readiness endpoint directly.
kubectl exec -it deploy/shadowai -- wget -qO- http://localhost:8080/api/ready
# Returns {"ready":false,"checks":{"db":{"ok":false},...}}

# If DB is down, check postgres pod.
kubectl get pods -l app=postgres
```

### SIEM Failure

**Alert:** `SIEMBatchDeliveryFailing`

```bash
# Check app logs for SIEM errors.
kubectl logs -l app.kubernetes.io/name=shadowai | grep "siem:"

# Verify SIEM endpoint is reachable from pods.
kubectl exec -it deploy/shadowai -- wget -O- ${SIEM_ENDPOINT}
```

Admin events continue to be written to `admin_event_logs` (DB truth) even when
SIEM is down. No data loss — only delivery delay.

### Audit Chain Break

**Alert:** `AuditChainBreakDetected` (CRITICAL)

1. **Do not restart or redeploy until investigated.**
2. Capture evidence:
   ```bash
   audit-verify --table all --verbose 2>&1 | tee /tmp/chain-break-$(date +%Y%m%d).log
   ```
3. Engage security team. This may indicate tampering.
4. Check recent DB access logs and admin_event_logs.

### Semantic V2 Degraded

**Alert:** `SemanticV2FailOpenHigh`

```bash
# Check embedding service.
kubectl exec -it deploy/shadowai -- wget -qO- ${FIREWALL_EMBEDDING_ENDPOINT}/health

# Temporarily disable SA_v2 without redeploying.
kubectl set env deployment/shadowai FIREWALL_SA_V2_ENABLED=false
# Re-enable after embedding service recovers.
```

### Semantic V2 Would-Block Review

**Alert:** `SemanticV2WouldBlockHigh`

Do not automatically promote to enforce while this alert is active. Review
samples using [semantic-v2-promotion.md](semantic-v2-promotion.md#would-block-review),
adjust corpus/thresholds if needed, rerun `firewall-bench --with-embeddings`,
then restart the shadow-only evidence window.

### Streaming Shadow Mismatch

**Alert:** `StreamingShadowMismatchHigh`

Streaming is in `shadow` mode — buffered is the source of truth. High mismatch
rate means `incremental` is NOT safe to promote:

1. Review `shadowai_streaming_shadow_mismatch_total{kind}` breakdown.
2. Check for new inspector configurations that may behave differently on
   response-side.
3. Do NOT set `STREAMING_MODE=incremental` until mismatch rate < 1%.

---

## Secret Rotation

```bash
# Rotate JWT secret (forces all users to re-login).
kubectl patch secret shadowai-secrets \
  --patch='{"stringData":{"jwtSecret":"<new-strong-secret>"}}'
kubectl rollout restart deployment/shadowai
```

---

## Scaling

```bash
# Manual scale (overrides HPA temporarily).
kubectl scale deployment/shadowai --replicas=5

# Re-enable HPA control.
kubectl autoscale deployment/shadowai \
  --min=3 --max=10 --cpu-percent=65
```

---

## Health Check Reference

| Endpoint        | Purpose           | Expected when healthy |
|-----------------|-------------------|----------------------|
| `GET /api/health` | Kubernetes liveness  | `200 {"status":"ok"}` |
| `GET /api/ready`  | Kubernetes readiness | `200 {"ready":true,...}` |
| `GET /metrics`    | Prometheus scrape    | text/plain metrics |

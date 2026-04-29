# ShadowAI Production Secret Matrix

All sensitive values must be injected via Kubernetes Secret `shadowai-secrets`.
Never commit plaintext values to values-prod.yaml or any version-controlled file.

## Core Secrets (always required)

| Secret key | Env var | Required? | Description |
|------------|---------|-----------|-------------|
| `databaseUrl` | `DATABASE_URL` | **REQUIRED** | Full Postgres DSN with sslmode=require |
| `jwtSecret` | `JWT_SECRET` | **REQUIRED** | ≥32 chars random; rotated = all users re-login |
| `redisUrl` | `REDIS_URL` | **REQUIRED** | Redis connection string with auth |

```bash
kubectl create secret generic shadowai-secrets \
  --namespace shadowai \
  --from-literal=databaseUrl='postgres://shadowai:PASS@host:5432/db?sslmode=require' \
  --from-literal=jwtSecret='<openssl rand -base64 48>' \
  --from-literal=redisUrl='redis://:PASS@redis:6379/0'
```

## Audit & WORM Secrets

| Secret key | Env var | Required? | Description |
|------------|---------|-----------|-------------|
| `auditChainSecret` | `AUDIT_CHAIN_SECRET` | **REQUIRED** in enterprise | ≥32 chars HMAC key for tamper-evident chain |
| `anchorSigningKey` | `AUDIT_ANCHOR_SIGNING_KEY` | If using immudb:// sink | Base64 Ed25519 private key |
| `anchorPubKey` | mounted file for `audit-export-evidence --pubkey-file` | If evidence export verifies signatures | Base64 Ed25519 public key used by evidence bundles |

## Evidence Export S3 Secrets (if `evidenceExport.storage=s3`)

| Secret key | Env var | Required? | Description |
|------------|---------|-----------|-------------|
| `s3AccessKeyID` | `AWS_ACCESS_KEY_ID` | If S3 evidence export enabled | Access key for S3-compatible bundle upload |
| `s3SecretAccessKey` | `AWS_SECRET_ACCESS_KEY` | If S3 evidence export enabled | Secret key for S3-compatible bundle upload |

The exact key names are configurable via:

```yaml
evidenceExport:
  s3:
    secretName: ""              # defaults to existingSecret
    accessKeyIDKey: s3AccessKeyID
    secretAccessKeyKey: s3SecretAccessKey
```

## SIEM Secrets

| Secret key | Env var | Required? | Description |
|------------|---------|-----------|-------------|
| `siemBearerToken` | `SIEM_BEARER_TOKEN` | If SIEM_ENABLED=true | Bearer token for SIEM endpoint |

## OIDC Secrets

| Secret key | Env var | Required? | Description |
|------------|---------|-----------|-------------|
| `oidcClientSecret` | `OIDC_CLIENT_SECRET` | If OIDC_ENABLED=true | OAuth2 client secret |

## MFA / Break-Glass Secrets

| Secret key | Env var | Required? | Description |
|------------|---------|-----------|-------------|
| `breakGlassSecretHash` | `BREAK_GLASS_SECRET_HASH` | If BREAK_GLASS_ENABLED=true | bcrypt hash of emergency password |

Generate: `htpasswd -bnBC 12 "" <password> | tr -d ':\n'`

## SCIM Secrets

| Secret key | Env var | Required? | Description |
|------------|---------|-----------|-------------|
| `scimBearerToken` | `SCIM_BEARER_TOKEN` | If SCIM_ENABLED=true | Token for IdP SCIM provisioning calls |

## immudb Secrets (if AUDIT_ANCHOR_SINK=immudb://)

| Secret key | Env var | Required? | Description |
|------------|---------|-----------|-------------|
| `immudbPassword` | `AUDIT_IMMUDB_PASSWORD` | If immudb sink enabled | immudb user password |

## Full Secret Creation (enterprise)

```bash
kubectl create secret generic shadowai-secrets \
  --namespace shadowai \
  --from-literal=databaseUrl='...' \
  --from-literal=jwtSecret='...' \
  --from-literal=redisUrl='...' \
  --from-literal=auditChainSecret='...' \
  --from-literal=anchorSigningKey='...' \
  --from-literal=anchorPubKey='...' \
  --from-literal=s3AccessKeyID='...' \
  --from-literal=s3SecretAccessKey='...' \
  --from-literal=siemBearerToken='...' \
  --from-literal=oidcClientSecret='...' \
  --from-literal=breakGlassSecretHash='...' \
  --from-literal=scimBearerToken='...'
```

## Secret Rotation

| Secret | Rotation impact | Procedure |
|--------|-----------------|-----------|
| `jwtSecret` | All users re-login | Rotate during low-traffic window; coordinate with ops |
| `breakGlassSecretHash` | Next break-glass use requires new password | Always rotate after use (see runbook) |
| `auditChainSecret` | Chain verification with old chain needs old key | Keep old key in cold storage for audit-verify |
| `anchorSigningKey` | New anchors use new key; old anchors use old key | Keep old public key for verify of historical anchors |
| `anchorPubKey` | New bundles include/verify against new public key | Keep old public keys for historical bundles |
| `s3AccessKeyID` / `s3SecretAccessKey` | Evidence export upload fails until Secret and bucket policy are updated | Rotate with S3 IAM user/access policy; run manual evidence export after rotation |
| `scimBearerToken` | IdP can't provision until updated | Coordinate with IdP team; update both simultaneously |

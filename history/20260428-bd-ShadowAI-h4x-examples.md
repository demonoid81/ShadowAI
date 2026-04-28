# bd-ShadowAI-h4x — примеры PROD1 validation pack

## Happy path 1: preflight до деплоя

Команда:

```bash
shadowai-prod-validate \
  --chart ./deploy/helm/shadowai \
  --values ./deploy/helm/shadowai/values-prod.yaml \
  --image-tag "$IMAGE_TAG" \
  --format json \
  --output prod1-preflight.json
```

Ожидание: exit `0`, `overall=pass`, `helm_template=pass`.

## Happy path 2: полный go/no-go

Команда включает `--live`, `--base-url`, `--evidence-bundle`, `--bucket`,
`--require-object-lock`.

Ожидание: exit `0`, все configured required checks проходят, report архивируется
как production readiness artifact.

## Edge case 1: нет настроенных checks

Команда:

```bash
shadowai-prod-validate
```

Ожидание: exit `2`, потому что пустая команда не должна создавать ложный pass.

## Edge case 2: MinIO / custom S3

Команда использует:

```bash
--endpoint http://minio.example.com:9000 --force-path-style
```

Ожидание: `audit-evidence-report` получает endpoint/path-style flags, а secrets
остаются в стандартных AWS env или instance credentials.

## Failure case 1: readiness failed

`/api/health` возвращает `200`, `/api/ready` возвращает `503`.

Ожидание: exit `1`, `http_ready=fail`, go-live запрещён до восстановления DB/Redis
или другой dependency, отражённой в readiness.

## Failure case 2: Object Lock posture failed

`audit-evidence-report` находит bundle без retention или с retention меньше policy.

Ожидание: exit `1`, `evidence_retention=fail`, bundle нельзя использовать как
compliance artifact до исправления bucket/Object Lock policy.

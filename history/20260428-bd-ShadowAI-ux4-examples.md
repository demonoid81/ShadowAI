# ShadowAI-ux4 examples

## Happy path 1: operator opens Settings

Admin открывает `/settings`. Экран показывает hero, live signal cards, read-only control families и secret-safety notes. В nav появляется пункт Settings в группе Operate.

## Happy path 2: readiness endpoint healthy

`GET /api/ready` возвращает `{"ready":true}`. Settings показывает live status `live ok` для DB / Redis readiness и текст, что service может принимать traffic.

## Edge case 1: readiness degraded

`GET /api/ready` возвращает 503 и checks с failed db/redis. Settings не падает и не показывает зелёный статус; card получает `failed` и перечисляет failed checks.

## Edge case 2: admin-only endpoint недоступен

Если `/proxy/firewall/status`, `/api/audit/status` или `/proxy/providers/connectivity` недоступны из-за роли или backend ошибки, card получает `unknown`, а не `ok`. Это защищает от fake-live posture.

## Edge case 3: provider registry без snapshot

Если provider connectivity summary показывает total=0 или snapshot отсутствует, Settings отображает `unknown`/review текст, а не утверждает, что providers healthy.

## Failure case 1: попытка редактировать secrets

UX4 не содержит форм для provider API keys, SCIM bearer tokens, SIEM tokens, OIDC secrets, JWT/audit/signing secrets или Vault credentials. Если такие поля понадобятся, это должна быть отдельная audited settings задача.

## Failure case 2: оператор принимает checklist за live state

Checklist cards имеют статус `checklist`, а не `live ok`. Это явно отделяет env/runbook controls от live endpoints.

# ShadowAI-9zi examples

## Happy path 1: production operator opens Settings

После `UX4` оператор открывает `/settings` и видит группы controls: Identity, SIEM, Evidence, Streaming, BYOK, Production. Для каждого блока понятно, является ли состояние live signal, configuration checklist или CLI/report workflow.

## Happy path 2: global admin manages tenant onboarding

После `UX5` global_admin открывает `/tenants`, создаёт организацию, выпускает SCIM token, настраивает org budget и видит предупреждение, что plaintext token показывается только один раз.

## Happy path 3: admin completes MFA challenge

После `UX6` admin вводит пароль, получает `mfa_required`, проходит MFA verify и получает полноценный JWT. Обычный 401 interceptor не ломает этот flow.

## Edge case 1: tenant admin tries cross-org action

Tenant admin открывает tenant UI. Действия за пределами его org скрыты или возвращают понятный 403/404, а UI не пытается кэшировать cross-org state.

## Edge case 2: compliance report has unknown fields

После `UX9` пользователь загружает retention/access-review JSON с дополнительными полями. Viewer показывает известные поля и не падает на расширениях schema.

## Failure case 1: operations signal отсутствует

После `UX10` если CronJob/Prometheus status недоступен через backend endpoint, UI показывает `unknown/not configured`, а не зелёный статус.

## Failure case 2: invalid governance policy

После `UX8` пользователь пытается сохранить context_scoped policy с пустыми provider rules или невалидной sensitivity. UI показывает validation error и не отправляет ambiguous allow-all policy.

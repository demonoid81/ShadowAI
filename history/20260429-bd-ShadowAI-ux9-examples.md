# ShadowAI-ux9 — Examples

## Happy path 1 — Access review

Вход: JSON с `users_summary`, `privileged_users` и `findings`.

Ожидаемый результат: report type `access_review`, status `fail` при `critical/high` finding, findings list показывает `admin_without_mfa`, rows preview показывает privileged users.

## Happy path 2 — Retention report

Вход: JSON с `bundles`, `total_bundles`, `compliant_count`, `violation_count`.

Ожидаемый результат: report type `retention_report`, status `fail` при `violation_count > 0`, findings list показывает key bundle и список retention violations.

## Edge case 1 — Evidence manifest with templates

Вход: `audit-collect-evidence` manifest с controls в статусах `collected`, `template`, `not_collected`.

Ожидаемый результат: status `warn`, not_collected count отражает только `not_collected`, template controls отображаются как informational findings.

## Edge case 2 — not_collected.json array

Вход: массив control entries без manifest wrapper.

Ожидаемый результат: report type `not_collected`, status `warn` если массив непустой, каждая строка превращается в finding с reason/description.

## Failure case — Invalid JSON

Вход: синтаксически некорректный JSON.

Ожидаемый результат: UI показывает safe error `invalidJson`, текущий report сбрасывается, файл не отправляется на backend.

## Unknown report

Вход: корректный JSON, который не похож на поддерживаемые CLI outputs.

Ожидаемый результат: report type `unknown`, status `unknown`, rows preview сохраняет raw object для ручного анализа.

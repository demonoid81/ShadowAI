# UX3 examples

## Happy path 1: tenant operator

Пользователь с admin-доступом открывает `/tenants`. Интерфейс показывает tenant boundary, per-org SCIM, org budgets, tenant evidence и scoped purge controls. Команды на странице ведут к реальным CLI artifacts: `audit-export-evidence --org-id`, `audit-purge --org-id`, `audit-verify --bundle`.

## Happy path 2: compliance auditor workflow

Пользователь открывает `/compliance`. Экран показывает SOC2/ISO mapping, quarterly evidence package, access review, retention posture и явный disclaimer, что это не сертификация. Команды соответствуют существующим CLI: `audit-collect-evidence`, `audit-access-review`, `audit-evidence-report`.

## Edge case 1: operations без live telemetry

Пользователь открывает `/operations` и ожидает live status. Экран не показывает зелёные/красные fake health indicators. Вместо этого он описывает runbook-порядок и команды, которые формируют проверяемые reports: production validation, restore drill, BYOK sweep и smoke suite.

## Edge case 2: локаль переключена на английский

При английской локали новые nav items и страницы используют `en.json`: Tenants, Compliance, Operations. Все тексты остаются согласованными с русской локалью и не выводят i18n key fallback.

## Failure case: отсутствует backend status API

Если в системе нет отдельного API для live compliance/operations status, новые страницы всё равно корректны: они являются capability/operations overview, а не мониторингом. Проверка фактического состояния остаётся через CLI reports, CronJobs и Prometheus alerts.

## Failure case: tenant bundle scope misunderstanding

Если auditor пытается трактовать tenant bundle как global proof, страница Tenants прямо отделяет tenant-scoped export от global inventory и указывает на Merkle subset proofs как на механизм tenant verification без раскрытия cross-tenant row hashes.

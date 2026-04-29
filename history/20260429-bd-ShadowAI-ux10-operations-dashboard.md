# ShadowAI-ux10 — Operations live health and dashboard accuracy

## Контекст

Dashboard показывал live usage metrics рядом со статическими readiness/posture cards. OperationsPage была runbook overview без live health. Это создавало риск, что оператор или бизнес-пользователь примет static capability marker за подтверждённый production health.

## Цель

Разделить live signals и static capability posture во frontend, добавить honest Operations live health на существующих безопасных endpoints и улучшить error/loading/empty states для Dashboard.

## План реализации

1. Проверить фактические источники данных: `/api/dashboard/*`, `/api/health`, `/api/ready`, `/proxy/firewall/status`, `/api/audit/status`.
2. Добавить чистые summarizer-функции для Operations live health.
3. Покрыть degraded/unknown/fail-safe cases unit-тестами.
4. Добавить loading/error/empty states в dashboard store и DashboardPage.
5. Добавить Operations live health section без Prometheus/CronJob claims.
6. Обновить ru/en i18n.
7. Выполнить frontend build и закрыть bd.

## Размышления

Рассмотрены два подхода: использовать SettingsPage live signal code напрямую или вынести отдельный Operations health слой. Принято решение вынести чистые summarizer-функции в `operationsHealth.ts`, потому что они тестируемы без браузера и фиксируют fail-safe семантику.

Рассмотрен вариант показывать CronJob/Prometheus/Kubernetes status как зелёный checklist. Альтернатива отклонена: без backend API это был бы fake live status. В v1 такие сигналы остаются runbook/static capability, а live блок показывает только реально вызванные HTTP endpoints.

Для Dashboard принято решение не менять backend API и не добавлять retry orchestration в scope v1. Вместо этого store теперь явно хранит loading/error states, а UI показывает failure/empty state вместо молчаливого отсутствия данных.

## Scope In

- Dashboard live/static labels.
- Dashboard loading/error/empty states для stats, usage, top users.
- Operations live health по `/api/health`, `/api/ready`, `/proxy/firewall/status`, `/api/audit/status`.
- Unknown state при недоступном сигнале.
- ru/en i18n.

## Scope Out

- Direct Prometheus API integration.
- Kubernetes CronJob live status без backend API.
- New backend endpoints.
- Claiming evidence export success from static config.

## Definition of Done

- Dashboard нельзя прочитать как полностью live production readiness.
- Failed dashboard API calls показывают полезные states.
- Operations показывает live readiness только для реально вызванных endpoints.
- Missing signal отображается как `unknown`, не зелёным статусом.
- `npm run build` проходит.

## Roadmap

v1: honest live/static split and endpoint health.

v2+: backend-backed CronJob/Prometheus summary endpoint, explicit retry controls, last-success timestamps.

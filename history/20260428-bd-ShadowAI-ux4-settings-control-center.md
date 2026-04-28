# ShadowAI-ux4: Settings & Admin Control Center read-only v1

## Контекст

Frontend после UX3 имеет enterprise shell и overview-страницы, но не имел единого места, где оператор видит configuration posture платформы. Backend уже предоставляет несколько безопасных read-only signals: readiness, firewall status, audit status и provider connectivity. Другие controls остаются env/CLI/CronJob driven и не должны выглядеть как live-green status в UI.

CASS недоступен в текущем workspace: `cass health` вернул неинициализированное хранилище. Источником истины были локальный код, bd `ShadowAI-ux4`, backend route registrations и frontend routes.

## Цель

Добавить `/settings` как read-only Admin Control Center: показать live signals только там, где есть backend endpoint, а остальное оформить как operator checklist без секретов и без write-actions.

## План реализации

1. Перевести `ShadowAI-ux4` в `in_progress`.
2. Проверить существующие endpoints: `/api/ready`, `/proxy/firewall/status`, `/api/audit/status`, `/proxy/providers/connectivity`.
3. Добавить route `/settings` и nav item в Operate.
4. Реализовать `SettingsPage.vue` с live signal cards, checklist controls и secret-safety notes.
5. Добавить ru/en i18n.
6. Проверить locale JSON, frontend build, diff-check, ast-index.
7. Закрыть bd и сделать commit.

## Размышления

Рассмотрены варианты: сделать editable settings UI, сделать полностью статичный overview или сделать read-only hybrid. Editable UI отклонён: большинство production settings являются env/secrets/config и требуют отдельного audited mutation workflow. Полностью статичный overview отклонён, потому что уже есть безопасные endpoints, которые дают реальный signal.

Принято решение сделать read-only hybrid: live cards используют только существующие endpoints; identity/SIEM/evidence/streaming/BYOK/production controls показаны как checklist, если прямого status API нет. Это сохраняет честность UI и не создаёт ложный green status.

## Реализованный contract

- `/settings` доступен через Operate navigation.
- Live signals:
  - `GET /api/ready`
  - `GET /proxy/firewall/status`
  - `GET /api/audit/status`
  - `GET /proxy/providers/connectivity`
- Checklist controls:
  - Identity controls
  - SIEM delivery
  - Evidence / WORM
  - Streaming / firewall gates
  - BYOK audit payloads
  - Production validation
- Secret boundary:
  - не выводятся API keys, SIEM tokens, SCIM tokens, break-glass hashes, OIDC secrets, JWT/audit/signing secrets, KMS/Vault credentials.

## Scope Out

- Изменение env/config из UI.
- Secret display.
- Новые backend endpoints.
- Prometheus/CronJob live dashboard.

## Roadmap

### v1

Read-only settings posture с безопасными live signals и checklists.

### v2+

- Editable settings только для backend-supported audited mutations.
- Dedicated status API для SIEM/evidence/CronJobs.
- Интеграция с UX5/UX6/UX10 для tenant/auth/operations workflows.

## Проверка

- `node -e "JSON.parse(...ru.json); JSON.parse(...en.json)"`
- `cd frontend && npm run build`
- `git diff --check`
- `ast-index update`

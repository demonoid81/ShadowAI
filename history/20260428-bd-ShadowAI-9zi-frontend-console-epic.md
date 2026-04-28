# ShadowAI-9zi: Full solution — Enterprise frontend console completion

## Контекст

Frontend уже покрывает основные продуктовые зоны на уровне shell и overview: Dashboard, Firewall, Evidence, Tenants, Compliance, Operations. Но рабочий UI ещё не соответствует всему backend-функционалу: многие возможности доступны только через CLI/API или представлены как статические capability pages.

## Цель

Довести frontend до состояния, где business/operator пользователь может выполнять ключевые enterprise workflows из UI либо видеть честный read-only status с понятным следующим действием.

## Epic decomposition

1. `ShadowAI-ux4` — Settings & Admin Control Center read-only v1.
2. `ShadowAI-ux5` — Tenant Admin CRUD and SCIM token management.
3. `ShadowAI-ux6` — Auth UX hardening: MFA, OIDC, break-glass and profile.
4. `ShadowAI-ux7` — Legal Holds and Admin Events UI.
5. `ShadowAI-ux8` — Governance Policy v2 UI.
6. `ShadowAI-ux9` — Compliance report workspace.
7. `ShadowAI-ux10` — Operations live health and dashboard accuracy.

## Размышления

Рассмотрены варианты: двигаться от самых заметных business screens или сначала закрыть technical correctness. Принято решение начать с `UX4 Settings`, потому что settings/control center станет общей опорой для production posture и ссылок на deeper workflows.

Tenant admin (`UX5`) выбран вторым по приоритету: backend API уже существует, а business value высокий. Auth UX (`UX6`) также P1, потому что backend security flows без UI создают риск неправильного использования продукта.

Legal holds, compliance workspace и live operations вынесены в P2: они важны для enterprise readiness, но могут идти после settings/tenant/auth/governance.

## Definition of Done для epic

- Все реализованные backend enterprise capabilities доступны из UI или представлены как честный read-only status/report workflow.
- Нет fake live-status без backend signal.
- Интерактивные страницы имеют loading/error/empty states.
- Role-sensitive actions скрываются или блокируются fail-safe.
- После каждой child-задачи `npm run build` проходит.

## Риски

- Governance builder может случайно упростить policy до небезопасного allow-all. Нужна fail-safe валидация.
- Auth UX может сломать 401 interceptor и MFA flow. Нужна отдельная проверка challenge state.
- Operations health легко переобещать. Любой отсутствующий signal должен отображаться как unknown/not configured.

## Roadmap

### v1

Закрыть UX4-UX10 в порядке P1 → P2:

- P1: UX4, UX5, UX6, UX8.
- P2: UX7, UX9, UX10.

### v2+

- Auditor portal с server-side evidence inventory.
- Policy simulation/dry-run endpoint и diff approval.
- Backend-backed Prometheus/CronJob summary endpoint.
- Tenant onboarding wizard.
- Расширенный profile/session/device management.

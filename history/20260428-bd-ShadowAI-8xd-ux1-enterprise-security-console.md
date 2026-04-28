# bd-ShadowAI-8xd — UX1 enterprise security console shell

## Контекст

Frontend визуально отставал от backend-возможностей: простая админ-панель с
emoji-навигацией и базовым dashboard не отражала WORM evidence, tenant isolation,
BYOK, SIEM, SCIM/OIDC/MFA, production validation и compliance posture.

CASS недоступен: база не инициализирована в текущем data-dir. Источники истины:
фактический frontend-код и roadmap.

## Цель

Сделать первый UI-слой, который позиционирует продукт как enterprise security
console, не ломая существующие routes и API calls.

## Scope In

- Новый `DashboardLayout.vue` с grouped navigation: Observe, Govern, Protect,
  Operate.
- Новый `DashboardPage.vue` с hero/posture cards и сохранёнными stats/usage/top
  users.
- CSS utilities для нового визуального языка.
- i18n ru/en для новых labels.

## Scope Out

- Полный rewrite всех страниц.
- Новые backend endpoints.
- Evidence/WORM dedicated UI.
- Tenant/org control plane UI.
- Новые frontend dependencies.

## Размышления

Рассмотрены варианты:

- “подкрасить” текущий sidebar и dashboard;
- переписать весь frontend;
- сделать UX1 shell + dashboard как enterprise security console.

Принято решение: UX1 shell + dashboard. Это меняет первое впечатление и
информационную архитектуру без большого риска regression. Глубокие страницы
останутся следующими UX2+ задачами.

Альтернатива “CSS polish” отклонена: она не решает mismatch между продуктовой
функциональностью и восприятием. Альтернатива full rewrite отклонена: слишком
широкий scope для одного PR.

## План реализации

1. Проверить baseline `npm run build`.
2. Переписать layout shell.
3. Переписать dashboard hero/posture.
4. Добавить CSS utilities и i18n.
5. Собрать frontend.
6. Провести self-review и commit.

## Roadmap

### v1

- Enterprise shell + posture dashboard.

### v2+

- Evidence/WORM UI.
- Tenant/org operations UI.
- Auditor/compliance workspace.
- Production validation report viewer.

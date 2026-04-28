# UX3: завершение покрытия enterprise frontend

## Контекст

После UX1/UX2 интерфейс уже имел enterprise shell, обновлённый dashboard и страницу Evidence/WORM. При этом часть реализованных backend-возможностей оставалась без отдельной навигационной зоны: tenant isolation, compliance workflow и production operations. Это создавало несоответствие между внешним видом продукта и фактическим функционалом backend.

CASS недоступен в текущем рабочем каталоге: `cass health` вернул состояние неинициализированного хранилища. Контекст восстановлен через локальные файлы, bd-задачу `ShadowAI-7yj` и фактический код frontend.

## Цель

Довести frontend v1 до логического конца без добавления новых backend API: добавить обзорные страницы, которые честно представляют реализованные enterprise/security capabilities и не показывают фиктивный live-status.

## План реализации

1. Расширить router тремя маршрутами: `/tenants`, `/compliance`, `/operations`.
2. Добавить пункты навигации в существующие группы: Govern, Evidence, Operate.
3. Реализовать `TenantsPage.vue` как overview tenant isolation, SCIM, org budgets, tenant purge и tenant evidence.
4. Реализовать `CompliancePage.vue` как auditor workspace для SOC2/ISO mapping, evidence collection, access review и retention posture.
5. Реализовать `OperationsPage.vue` как production operations cockpit для go/no-go validation, SIEM, restore drills и BYOK rollout.
6. Добавить ru/en i18n ключи для всех новых экранов.
7. Проверить сборку фронта и зафиксировать результат в bd/history/commit.

## Размышления

Рассмотрены варианты: сделать CRUD-экраны для организаций и SCIM tokens, сделать live operations dashboard, либо ограничиться capability-oriented страницами. Полный CRUD отклонён, потому что он требует нового UX/API-контракта и выходит за рамки задачи. Live dashboard отклонён, потому что без отдельного backend status API он создавал бы ложное ощущение мониторинга.

Принято решение сделать честный enterprise console v1: страницы показывают capability model, реальные CLI/artifact commands и caveats. Это закрывает визуальный разрыв с backend-функционалом, но не переобещает runtime state.

## Scope In

- Маршруты `/tenants`, `/compliance`, `/operations`.
- Навигация в существующем dashboard layout.
- Статические capability pages без новых зависимостей.
- Полная ru/en локализация.
- История и примеры.

## Scope Out

- Live API для org/compliance/ops health.
- CRUD организаций и SCIM tokens.
- Auditor file-upload workspace.
- Новые frontend dependencies.

## Roadmap

### v1

- Enterprise console покрывает основные зоны: dashboard, firewall, evidence, tenants, compliance, operations.
- Новые страницы являются overview/control-plane слоями и используют существующую visual system.

### v2+

- Tenant CRUD и SCIM token UI поверх существующих enterprise API.
- Compliance workspace с загрузкой/проверкой bundle-файлов.
- Operations live health page на базе readiness, CronJob status и Prometheus-derived signals.

## Проверка

- `cd frontend && npm run build`
- `node -e "JSON.parse(...ru.json); JSON.parse(...en.json)"`
- `git diff --check`
- `ast-index update`

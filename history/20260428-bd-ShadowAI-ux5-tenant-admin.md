Тема: bd ShadowAI-ux5 — Tenant Admin CRUD and SCIM token management

Контекст
Frontend `/tenants` был capability overview и не позволял оператору управлять реализованными backend controls: `/api/orgs/*`, per-org SCIM tokens и org budget.

Допущения
Задача понятна частично: пользователь дал команду продолжать реализацию после UX4, поэтому взята следующая задача frontend-эпика по roadmap — UX5.
CASS недоступен в текущем data dir, поэтому источником истины стали bd-задача и фактический код.

Размышления
Рассмотрены варианты: оставить обзорную страницу и добавить ссылки на CLI, либо сделать рабочий UI поверх существующих backend endpoints. Принято решение реализовать рабочий UI без новых backend endpoints. Альтернатива с mock/live-fake статусами отклонена: ошибки 403/404/409 показываются явно, backend остаётся источником истины.

Принятые решения
- `global_admin` загружает `/api/orgs` и может создавать организации.
- Tenant admin не вызывает `/api/orgs`; он загружает только `/api/orgs/{org_id}` из authenticated JWT claims.
- Plaintext SCIM token хранится только в состоянии текущей страницы и может быть очищен оператором; после reload он недоступен.
- Org budget редактируется только через `/api/orgs/{org_id}/budget`; UI не делает аналитику spend beyond current status.
- `auth.isAdmin` включает `global_admin`, иначе frontend навигация скрывала бы enterprise admin pages.

План реализации
1. Добавить typed API wrapper для organizations, SCIM tokens и org budget.
2. Разбить Tenants UI на компоненты: org list, org detail, SCIM tokens, budget.
3. Обновить `/tenants` на role-aware рабочий экран.
4. Добавить utility logic и lightweight тест для role/budget/token helpers.
5. Добавить ru/en локализацию и history examples.
6. Проверить build, locale parse, ast-index и git diff.

Definition of Done
- `global_admin` может list/create/update org.
- Tenant admin может видеть и обновлять свой org, SCIM tokens и budget.
- Plaintext SCIM token показывается только после create.
- Ошибки 403/404/409 отображаются понятными сообщениями.
- `npm run build` проходит.

Roadmap
v1: org CRUD + SCIM token management + budget form.
v2+: SCIM sync status, IdP mapping preview, tenant onboarding wizard, backend-backed role/permission discovery.

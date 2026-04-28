# Остатки frontend после UX3

## Тема / вопрос

Что ещё не реализовано на frontend: dashboard, настройки, tenant/compliance/operations и связанные enterprise-функции.

## Контекст

Фактический код frontend содержит маршруты:

- `/dashboard`
- `/audit`
- `/policies`
- `/budget`
- `/tenants`
- `/users`
- `/providers`
- `/firewall`
- `/evidence`
- `/compliance`
- `/operations`
- `/internal-db`

Новые страницы `/tenants`, `/compliance`, `/operations` являются capability overview и не вызывают backend API. Это было сознательное ограничение UX3, чтобы не показывать фиктивный live-status без отдельного backend-контракта.

CASS недоступен в текущем каталоге: `cass health` вернул состояние неинициализированного индекса. Анализ выполнен по фактическим файлам `frontend/src` и backend route registrations.

## Размышления

Рассмотрены варианты: считать frontend завершённым после overview-страниц или выделить оставшиеся interactive gaps. Принято решение считать UX3 завершением визуального покрытия, но не завершением full operator UI.

Альтернатива "сразу делать всё" отклонена как слишком широкая: настройки, tenant admin, compliance, MFA/OIDC/SCIM, legal holds и production health требуют разные API contracts и разные UX-модели. Рациональнее закрывать по задачам.

## Что реализовано на frontend

- Dashboard: summary stats, usage chart, top users, posture cards.
- Audit logs: список audit rows с фильтрами.
- Policies: базовый CRUD policy rules.
- Budget: per-user budget view.
- Users: list/create/update role/active.
- Providers: list/connectivity/test.
- Firewall: status + recent blocked logs.
- Internal DB: source list + query execution.
- Evidence/Tenants/Compliance/Operations: overview/capability pages.
- Auth: login/register/logout.

## Что не реализовано на frontend

1. Settings / Configuration center.
   Нет единого экрана настроек для env/config posture, streaming gates, SIEM, evidence sinks, BYOK, OIDC/SCIM/MFA и production validation.

2. Tenant admin UI.
   Backend имеет `/api/orgs/*`, SCIM tokens и org budget API, но frontend `/tenants` пока только overview. Нет list/create/update org, SCIM token management, org budget editor.

3. Governance policy UI v2.
   Backend имеет enterprise governance `/api/governance/policy` с role/context scoped routing, department/sensitivity, provider rules. Frontend сейчас показывает legacy `/api/policies` и не даёт управлять context_scoped policy.

4. Admin events UI.
   Backend имеет `/api/admin-events`, SIEM/admin audit trail, source_org_id/target_org_id. Отдельного UI для admin activity/audit trail нет.

5. Legal hold / DSAR UI.
   Backend имеет legal hold lifecycle, approve/reject/release, bulk actions, pending SLA. Frontend не имеет экрана legal holds.

6. MFA / break-glass / OIDC flow UI.
   Backend поддерживает MFA setup/confirm/verify, break-glass, OIDC login/callback. Frontend login store ожидает только `token`, не обрабатывает `mfa_required`, `mfa_token`, OIDC login button, MFA enrollment или break-glass.

7. SCIM admin UI.
   SCIM protocol endpoints есть для IdP, но frontend не показывает SCIM status, tokens, mappings или provisioning health.

8. Compliance interactive workspace.
   `/compliance` пока overview. Нет запуска/загрузки evidence packages, просмотра `not_collected`, access review report, retention audit report.

9. Operations live health.
   `/operations` пока runbook page. Нет live readiness, CronJob status, Prometheus alert summary, evidence export status, restore drill history.

10. Dashboard accuracy.
   Dashboard смешивает live stats с статическими readiness cards. Нет явного разделения "live metrics" и "capability posture"; нет error/loading/empty states для всех секций.

11. User/profile settings.
   Нет личного профиля пользователя: API key rotate/revoke UI, MFA self-enrollment, department display, org_id/global_admin visibility.

12. Provider/governance depth.
   Providers page проверяет connectivity, но не даёт настраивать provider routing, model allowlists, department/sensitivity policies или fallback behavior.

## Рекомендованное направление

Следующая задача должна быть `UX4 Settings & Admin Control Center`.

Причина: settings/control center станет навигационной основой для production use. В него можно честно вынести:

- runtime config posture,
- identity controls,
- evidence controls,
- streaming/firewall gates,
- org/current tenant context,
- ссылки на deeper admin screens.

После этого логично брать `UX5 Tenant Admin CRUD`, потому что backend API уже есть и это самый заметный business-facing gap.

## Открытые вопросы

- Делать settings как read-only posture сначала или сразу с write-actions?
- Настройки должны быть одним экраном `/settings` или секциями внутри `/operations`?
- Нужен ли отдельный `/admin-events` экран перед legal holds?

## Возможные следующие шаги

1. UX4: Settings & Admin Control Center read-only v1.
2. UX5: Tenant Admin CRUD + SCIM token management.
3. UX6: Auth UX hardening — MFA, OIDC login, break-glass.
4. UX7: Legal Holds + Admin Events UI.
5. UX8: Compliance workspace with evidence report viewer.

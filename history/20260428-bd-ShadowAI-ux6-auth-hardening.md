Тема: bd ShadowAI-ux6 — Auth UX hardening

Контекст
Backend уже поддерживает password+MFA challenge, TOTP setup/confirm/disable, OIDC login/callback, break-glass и API key rotation/revoke. Frontend login flow до UX6 ожидал только `{token}` и не показывал эти security flows.

Допущения
Пользователь разрешил выполнять задачи по порядку. По roadmap после UX4 и UX5 следующая задача — UX6. CASS недоступен в текущем data dir, поэтому использованы bd-задача и фактические backend handlers.

Размышления
Рассмотрены варианты: делать отдельные полноценные onboarding wizards или добавить v1 security/profile workflow поверх существующих endpoints. Принято решение v1 без новых backend endpoints: MFA challenge page, security profile, OIDC entrypoint и break-glass flow. Альтернатива с определением OIDC/MFA config в UI отклонена, потому что backend не предоставляет безопасный config-discovery endpoint.

Принятые решения
- Login обрабатывает оба ответа backend: `{token}` и `{mfa_required:true,mfa_token}`.
- MFA challenge token хранится только в `sessionStorage` и Pinia state, не в `localStorage`.
- Public auth endpoints с 401 (`login`, `mfa/verify`, `break-glass`) не запускают global redirect interceptor, чтобы UI мог показать ошибку.
- Break-glass вынесен в отдельный emergency mode на login screen с warning.
- Security page показывает session claims, MFA setup/confirm/disable, API key rotate/revoke и OIDC entrypoint.
- OIDC link указывает на `/api/auth/oidc/login`; если OIDC не настроен, backend возвращает безопасную ошибку/404.

План реализации
1. Добавить typed auth API wrapper.
2. Обновить auth store под MFA challenge и break-glass.
3. Добавить `/mfa/verify` и `/security` routes.
4. Обновить LoginPage под password/OIDC/break-glass.
5. Добавить SecurityPage для MFA/profile/API key.
6. Добавить i18n, helper tests, build checks.

Definition of Done
- Password login with MFA ведёт на MFA verify.
- MFA setup не сохраняет pending secret в DB до confirm — UI использует setup_token contract.
- Break-glass отделён от обычного login и содержит risk warning.
- API key rotate/revoke доступны пользователю.
- `npm run build` проходит.

Roadmap
v1: MFA/OIDC/break-glass/profile basics.
v2+: QR rendering, recovery codes, session/device inventory, backend config-discovery endpoint.

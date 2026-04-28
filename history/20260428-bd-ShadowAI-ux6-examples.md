Тема: bd ShadowAI-ux6 — примеры поведения

Happy path 1 — password login без MFA
1. Пользователь вводит email/password.
2. Backend возвращает `{token}`.
3. Frontend сохраняет JWT в `localStorage` и открывает dashboard или security enrollment для admin без MFA claim.

Happy path 2 — password login с MFA
1. Backend возвращает `{mfa_required:true,mfa_token}`.
2. Frontend сохраняет challenge token в `sessionStorage`, не в `localStorage`.
3. Пользователь вводит TOTP code на `/mfa/verify`.
4. Backend возвращает full JWT, frontend очищает challenge token.

Edge case 1 — MFA setup без lockout
1. Authenticated admin нажимает start MFA setup.
2. Backend возвращает `uri` и `setup_token`.
3. Frontend показывает URI и отправляет confirm только после ввода code.
4. До confirm secret не сохраняется в DB backend-ом.

Edge case 2 — OIDC не настроен
1. Пользователь нажимает OIDC login.
2. Browser переходит на `/api/auth/oidc/login`.
3. Если backend не зарегистрировал route, пользователь получает backend 404/ошибку; UI не утверждает, что OIDC точно включён.

Failure case — invalid MFA code
1. `/api/auth/mfa/verify` возвращает 401.
2. Interceptor не редиректит автоматически на `/login`, потому что это public auth endpoint.
3. MFA page показывает ошибку и даёт повторить ввод.

Failure case — break-glass denied
1. Пользователь открывает emergency mode и вводит неверный secret.
2. Backend возвращает 401/429.
3. UI показывает ошибку, не создаёт обычную сессию и не скрывает risk warning.

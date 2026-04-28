Тема: bd ShadowAI-ux5 — примеры поведения

Happy path 1 — global_admin создаёт организацию
1. Пользователь с role=`global_admin` открывает `/tenants`.
2. UI вызывает `GET /api/orgs`.
3. Оператор вводит name+slug и отправляет форму.
4. UI вызывает `POST /api/orgs`, добавляет новую организацию в список и выбирает её.

Happy path 2 — tenant admin управляет своим org
1. Пользователь с role=`admin` и `org_id=org-a` открывает `/tenants`.
2. UI не вызывает `GET /api/orgs`.
3. UI вызывает `GET /api/orgs/org-a`, затем SCIM и budget endpoints только для `org-a`.
4. Cross-org действия недоступны в интерфейсе.

Edge case 1 — SCIM plaintext token
1. Оператор создаёт SCIM token.
2. Backend возвращает `plain_token`.
3. UI показывает warning и token один раз в текущем состоянии страницы.
4. После clear/reload token не восстанавливается frontend-ом.

Edge case 2 — org budget observe mode
1. Оператор выбирает mode=`observe`.
2. UI отправляет `monthly_limit_cents` и `mode` без локального enforcement.
3. Backend сохраняет policy; UI перезагружает status и показывает spent/remaining.

Failure case — backend запрещает операцию
1. Backend возвращает 403, 404 или 409.
2. UI показывает понятное сообщение: недостаточно прав, not found или conflict.
3. UI не делает optimistic success и не скрывает ошибку.

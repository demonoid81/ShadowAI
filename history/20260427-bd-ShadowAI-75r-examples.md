# ShadowAI-75r — примеры поведения

## Happy path 1 — erasure внутри tenant

Tenant admin из `org_a` вызывает DSAR erasure для пользователя из `org_a`.

Ожидаемое поведение:

- target user находится через `GetByIDScoped(targetID, org_a)`;
- eraser вызывается как `EraseUserInOrg(actorID, targetID, org_a)`;
- `user_erasure_runs.org_id = org_a`;
- admin event содержит `target_org_id = org_a`.

## Happy path 2 — legal hold внутри tenant

Tenant admin из `org_a` создаёт legal hold для пользователя из `org_a`.

Ожидаемое поведение:

- handler резолвит target user через org-scoped lookup;
- service вызывает `CreateHoldInOrg`;
- `legal_holds.org_id = org_a`;
- `legal_hold_events.org_id = org_a`.

## Happy path 3 — per-user budget внутри tenant

Tenant admin из `org_a` обновляет budget пользователя из `org_a`.

Ожидаемое поведение:

- request проходит authorization;
- budget update выполняется;
- пользователь из другого org не затрагивается.

## Edge case 1 — global_admin

`global_admin` управляет target user из любого org.

Ожидаемое поведение:

- mandatory MFA считает `global_admin` privileged role;
- OIDC preflight требует IdP MFA для будущего `global_admin`;
- org lookup идёт через global `GetByID`, а не через scoped lookup.

## Edge case 2 — break-glass

Break-glass token выполняет emergency operation.

Ожидаемое поведение:

- operation допускается как explicit global emergency path;
- target org резолвится из DB;
- audit metadata сохраняет target org, если target user найден.

## Failure case 1 — cross-org erasure

Tenant admin из `org_a` пытается стереть пользователя из `org_b`.

Ожидаемое поведение:

- `GetByIDScoped(targetID, org_a)` не находит пользователя;
- endpoint возвращает `404 user not found`;
- eraser не вызывается;
- cross-tenant existence не раскрывается.

## Failure case 2 — cross-org legal hold

Tenant admin из `org_a` пытается создать legal hold на пользователя из `org_b`.

Ожидаемое поведение:

- handler не создаёт hold;
- возвращается `404 user not found`;
- `legal_holds` и `legal_hold_events` не получают строк.

## Failure case 3 — migration 020 на fresh PostgreSQL

Migration 020 выполняется на новой БД.

Ожидаемое поведение:

- не используется PostgreSQL-invalid `ADD CONSTRAINT IF NOT EXISTS`;
- check constraints создаются через `DO` block;
- legal hold release actions/statuses допустимы для `legal_hold_events`.

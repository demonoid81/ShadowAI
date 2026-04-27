# ShadowAI-75r — исправление blockers после senior review

## Контекст

Полное ревью проекта выявило несколько release-blocker и security gaps в tenant-aware enterprise ветке:

- enterprise migration 020 содержала PostgreSQL-несовместимый `ADD CONSTRAINT IF NOT EXISTS`;
- `global_admin` не был везде приравнен к privileged admin для MFA/OIDC preflight;
- DSAR erasure, per-user budget и legal hold операции не везде проверяли принадлежность target user к org;
- `legal_hold_events` не получал `org_id`;
- tenant list для `admin_event_logs` не учитывал `source_org_id` / `target_org_id`.

CASS был проверен перед реализацией, но индекс был stale/unhealthy. Поэтому источником истины стали фактический код, миграции, bd-задача и локальные regression tests.

## Цель

Закрыть найденные blockers без изменения публичной модели ролей и без затрагивания несвязанных dirty-файлов в рабочем дереве.

## Размышления

Рассмотрены варианты для tenant scope:

- переписать все repository update SQL на `WHERE id = $1 AND org_id = $2`;
- добавить scoped repository методы с предварительной проверкой ownership;
- оставить фильтрацию только на handler-level.

Принято решение использовать handler/service-level ownership checks и scoped repository methods там, где запись должна сохранить `org_id`. Такой вариант минимален по площади изменения и закрывает cross-tenant доступ на публичных entry points. Полная SQL-перепись всех legal hold transitions отклонена как более широкий refactor с высоким риском регрессий в уже работающей 4-eyes state machine.

Рассмотрены варианты для `global_admin`:

- оставить отдельные проверки `role == "admin"`;
- заменить все privileged checks на helper;
- расширить только OIDC preflight.

Принято решение ввести единый `auth.IsPrivilegedAdminRole`, чтобы `admin` и `global_admin` интерпретировались одинаково в mandatory MFA и OIDC MFA-gate. Частичная правка отклонена, потому что она сохраняла бы future drift.

Рассмотрены варианты для migration 020:

- удалить старые constraints без проверки;
- добавить новые constraints с `ALTER TABLE ... ADD CONSTRAINT IF NOT EXISTS`;
- использовать `DO $$ ... pg_constraint ... $$`.

Принято решение использовать `DO` blocks и явную проверку `pg_constraint`, потому что PostgreSQL не поддерживает `ADD CONSTRAINT IF NOT EXISTS`, а migration должна быть идемпотентной.

## План реализации

1. Добавить regression tests для MFA/global_admin, tenant-scoped erasure, budget, legal hold и admin audit list.
2. Исправить migration 020 через PostgreSQL-safe `DO` blocks и обновить check constraints для новых legal hold event actions/statuses.
3. Ввести privileged-admin helper и применить его в auth middleware и OIDC preflight.
4. Добавить org ownership checks для erasure, per-user budget и legal hold handlers/services/repositories.
5. Пропагировать `org_id` в `legal_holds`, `legal_hold_events` и `user_erasure_runs`.
6. Исправить tenant visibility для `admin_event_logs` по `org_id OR source_org_id OR target_org_id`.
7. Прогнать targeted, core, enterprise, integration, smoke и helm checks.

## Definition of Done

- Fresh enterprise migrations проходят на PostgreSQL.
- `ADMIN_MFA_REQUIRED` и OIDC MFA preflight покрывают `admin` и `global_admin`.
- Tenant admin не может управлять erasure, legal hold или per-user budget пользователя другого org.
- `legal_holds`, `legal_hold_events`, `user_erasure_runs` получают корректный `org_id`.
- Tenant list для admin audit включает события, где org является actor/source/target.
- Regression tests и полные проверки проходят.

## Проверка

- `go test -tags enterprise ./internal/auth ./internal/oidcauth ./internal/legalhold ./internal/budget ./internal/adminaudit -count=1`
- `go test ./... -count=1`
- `go test -tags enterprise ./... -count=1`
- `go test -tags 'enterprise integration' ./integration/... -count=1`
- `go test -tags 'enterprise smoke' ./smoke/... -count=1`
- `make helm-validate`
- `git diff --check`

## Риски / зависимости

- В рабочем дереве уже были несвязанные dirty-файлы; они не должны попадать в scope коммита.
- Scoped legal hold methods используют ownership precheck перед legacy transition. Это допустимо, потому что `legal_holds.org_id` является immutable ownership field, но full SQL-scoped transition rewrite можно вынести в v2 hardening.
- `legal_hold_events` пока использует существующий WORM canonical для event payload; `org_id` хранится в колонке и FK/tenant scope, но не меняет legacy canonical.

## Roadmap

### v1

- Закрыть найденные review blockers.
- Добавить regression coverage.
- Вернуть migration/integration path в зелёное состояние.

### v2+

- Рассмотреть scoped SQL rewrite для всех legal hold transition queries.
- Рассмотреть canonical v2 для `legal_hold_events`, если потребуется криптографически включить `org_id` события в WORM payload.
- Добавить отдельные smoke-сценарии для cross-org legal hold release transitions.

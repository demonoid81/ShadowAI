# Полное ревью проекта

## Тема / вопрос

Провести полное ревью проекта ShadowAI как senior developer.

## Контекст

Ревью выполнено в режиме DISCUSSION без исправления кода. Цель — найти риски корректности, безопасности, tenant isolation, evidence/compliance и операционной готовности.

CASS проверен перед началом: `cass health` вернул unhealthy из-за stale index. Поэтому контекст восстанавливался по локальному коду, ast-index и проверкам сборки/тестов.

Рабочее дерево на момент ревью было dirty до начала проверки; найденные выводы относятся к текущему состоянию файлов в workspace.

## Размышления

Рассмотрены варианты ревью: ограничиться статикой, запустить только unit tests, либо дополнить ревью smoke/integration проверками с PostgreSQL. Принято решение выполнять и статическую, и динамическую проверку, потому что проект содержит миграции, WORM/evidence и tenant isolation, где unit tests не покрывают deploy-time failures.

Альтернатива «доверять зелёному `go test ./...`» отклонена: обычный test suite не применяет enterprise migration 020 на реальной БД, а именно там обнаружен release-blocker.

## Варианты / области проверки

- Build/test health: core, enterprise, vet, Helm, CLI build.
- Enterprise deployability: smoke/integration с реальным PostgreSQL.
- Tenant isolation: admin routes, DSAR, legal hold, per-user budgets, admin audit visibility.
- MFA/OIDC: privileged role coverage for `admin` and `global_admin`.
- Evidence/WORM: tenant-scoped artifacts and legal hold event attribution.

## Найденные ключевые проблемы

1. Enterprise migration 020 не применима на PostgreSQL: `ALTER TABLE ... ADD CONSTRAINT IF NOT EXISTS` вызывает syntax error. Это блокирует fresh enterprise deploy, smoke и integration tests.

2. `ADMIN_MFA_REQUIRED` и OIDC MFA preflight проверяют только `admin`, но не `global_admin`. Более привилегированная роль может пройти без обязательной MFA.

3. Legal hold не tenant-scoped на уровне handler/service/repository: `legal_holds.org_id` и `legal_hold_events.org_id` есть в schema, но не заполняются бизнес-логикой. Tenant admin может работать с hold для чужого пользователя при знании ID.

4. DSAR erasure endpoint не проверяет org владельца target user и пишет `user_erasure_runs` без `org_id`. Tenant admin может удалить пользователя другого tenant при знании ID.

5. Per-user budget endpoint и repository работают только по `user_id`, без проверки `users.org_id`. Tenant admin может читать/изменять бюджет пользователя другого tenant.

6. Admin audit visibility для `global_admin`/cross-org действий непоследовательна: context содержит `claims.OrgID`, а list фильтрует только `admin_event_logs.org_id`, не учитывая `source_org_id`/`target_org_id`.

## Выполненные проверки

- `go test ./... -count=1` в `backend` — успешно.
- `go test -tags enterprise ./... -count=1` в `backend` — успешно.
- `go vet ./...` — успешно.
- `go vet -tags enterprise ./...` — успешно.
- `make helm-validate` — успешно.
- `make build-cli` — успешно.
- `go test ./cmd/audit-access-review ./cmd/audit-collect-evidence ./cmd/audit-evidence-report ./cmd/evidence-upload -count=1` — успешно.
- `go test -tags enterprise ./internal/chain ./internal/auth ./internal/legalhold -count=1` — успешно.
- `go test -tags 'enterprise integration' ./integration/... -count=1` — failed на migration 020.
- `go test -tags 'enterprise smoke' ./smoke/... -count=1` — failed на migration 020.
- `git diff --check` — успешно.
- `ubs backend --format=json` — нашёл warnings/critical candidates; actionable high-risk findings перепроверены вручную по коду.

## Рекомендованное направление

Первым исправить migration 020, потому что она блокирует fresh deploy и все smoke/integration сценарии. После этого закрывать tenant-isolation authorization gaps: DSAR, legal hold, per-user budgets. Затем расширить MFA checks на `global_admin` и поправить admin audit query semantics для source/target org.

## Открытые вопросы

- Должен ли `global_admin` видеть все `admin_event_logs` через `/api/admin-events`, или только события, где он source/target? Текущие комментарии и реализация расходятся.
- Должен ли `global_admin` иметь доступ к governance/legal hold/internal-db admin routes, или только к `/api/orgs/*`? Сейчас часть routes пропускает его на subrouter, но handler-level checks отклоняют.
- Нужна ли canonical v2 для `legal_hold_events` с `org_id`, или для WORM достаточно отдельного schema-level `org_id` без включения в HMAC canonical?

## Возможные следующие шаги

1. Исправить migration 020 через DO-block с проверкой `pg_constraint`, затем перезапустить smoke/integration.
2. Ввести общий helper для privileged role checks: `admin` + `global_admin`, отдельно от tenant access checks.
3. Добавить scoped service/repository методы для legal hold, erasure и per-user budgets.
4. Добавить smoke tests для cross-org denial: legal hold, DSAR erase, budget read/update.
5. Уточнить и реализовать admin audit visibility policy для `source_org_id`/`target_org_id`.

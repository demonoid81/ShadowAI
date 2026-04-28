# ShadowAI-6yu: создание frontend epic и UX-задач

## Контекст

После UX3 интерфейс получил визуальное покрытие enterprise console, но не полный interactive operator UI. Ранее это зафиксировано в `history/20260428-discussion-frontend-remaining-gaps.md`: отсутствуют settings, tenant CRUD, governance v2 UI, auth hardening, legal holds/admin events, compliance workspace и live operations health.

CASS недоступен в текущем рабочем каталоге: `cass health` вернул неинициализированное хранилище. Источником контекста стали фактический frontend/backend код, bd и history.

## Цель

Создать persistent roadmap в bd: один epic и набор конкретных child-задач, которые можно брать в работу по очереди.

## План

1. Создать служебную задачу `ShadowAI-6yu` и перевести её в `in_progress`.
2. Создать epic `ShadowAI-9zi`.
3. Создать дочерние задачи `ShadowAI-ux4` ... `ShadowAI-ux10`.
4. Связать задачи с epic через parent-child.
5. Зафиксировать roadmap и примеры в history.
6. Закрыть `ShadowAI-6yu` и сделать commit.

## Размышления

Рассмотрены варианты: создать одну крупную задачу "доделать фронт" или разложить на независимые UX-задачи. Одна крупная задача отклонена: scope слишком широкий и приведёт к смешиванию auth, tenant, compliance и operations workflows.

Принято решение создать один full-solution epic и семь child-задач. Это сохраняет общую цель, но позволяет реализовывать фронт по слоям и проверять каждую часть отдельно.

Альтернатива с немедленной реализацией UX4 отклонена в рамках этой задачи: пользователь запросил именно epic и задачи.

## Созданные bd issues

- `ShadowAI-9zi` — Full solution: Enterprise frontend console completion.
- `ShadowAI-ux4` — Settings & Admin Control Center read-only v1.
- `ShadowAI-ux5` — Tenant Admin CRUD and SCIM token management.
- `ShadowAI-ux6` — Auth UX hardening: MFA, OIDC, break-glass and profile.
- `ShadowAI-ux7` — Legal Holds and Admin Events UI.
- `ShadowAI-ux8` — Governance Policy v2 UI.
- `ShadowAI-ux9` — Compliance report workspace.
- `ShadowAI-ux10` — Operations live health and dashboard accuracy.

## Проверка

- `bd show ShadowAI-ux4 --json` подтвердил parent `ShadowAI-9zi`.
- `bd dep list ShadowAI-ux4 --json` подтвердил `parent-child`.
- `git diff --check` должен пройти перед commit.

## Roadmap

### v1

Закрыть UX4-UX10 по отдельным PR/commit: read-only settings, tenant admin, auth UX, legal/admin events, governance v2, compliance reports, operations live/static split.

### v2+

Добавить server-side report inventory, auditor portal, backend-backed CronJob/Prometheus summary, policy simulation/diff approval и расширенные profile/session controls.

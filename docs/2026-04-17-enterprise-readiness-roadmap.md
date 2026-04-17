# ShadowAI Enterprise Readiness Roadmap

Дата: 2026-04-17

## Цель

Зафиксировать, чего не хватает ShadowAI до состояния:

1. `enterprise pilot ready`
2. `signed production ready`
3. `broader GA / hardened default`

Документ отражает текущее состояние после:

- `semantic_v2` benchmark и baseline
- `PR-A` audit privacy hardening
- inspector modes / shadow rollout support
- benchmark harness / observability

---

## Текущий статус

### Уже сделано

- Firewall pipeline покрывает proxy endpoints.
- Есть `semantic_v2` и baseline на реальном прогоне.
- Есть `shadow/enforce/disabled` режимы инспекторов.
- Есть Prometheus metrics и audit privacy hardening.
- Есть `AUDIT_PAYLOAD_MODE`, retention, purge CLI и purge scheduler.
- Admin-only access для audit/firewall status уже включён.

### Уже не блокирует prod в одиночку

- Prompt injection / jailbreak detection baseline.
- Basic audit durability.
- Secure-by-default audit payload handling.
- Shadow rollout mechanics.

### Что всё ещё блокирует “enterprise/business-ready”

- Нет DSAR / erasure workflow.
- Нет tenant isolation.
- Нет enterprise auth (`OIDC/SAML/MFA`).
- Нет admin access audit.
- Нет provider governance по residency / approved subprocessors.
- Нет prod fail-fast на небезопасный config.
- Нет Stage 2 streaming passthrough для hardened default.

---

## Roadmap 0-30 дней

### Must-Have for Enterprise Pilot

#### 1. PR-B: DSAR / Erasure Workflow

Цель: уметь удалить или необратимо анонимизировать данные пользователя.

Почему это первое:

- После `PR-A` это самый заметный privacy/compliance gap.
- Это частый blocker в enterprise questionnaire.
- Это сильнее влияет на бизнес-риск, чем ещё один detector upgrade.

Скоуп:

- admin-only command/API для `erase user data`
- anonymize или delete user profile
- anonymize audit rows по `user_id`
- policy для `shadow_decisions_json`
- идемпотентное повторное выполнение
- admin event log на сам факт erasure

Acceptance criteria:

- по `user_id` можно убрать связь audit trail ↔ конкретный человек
- повторный вызов не ломает систему
- операция документирована для ops/legal

#### 2. PR-C: Prod Config Hardening

Цель: fail-fast на небезопасной prod-конфигурации.

Скоуп:

- запрет placeholder `JWT_SECRET` в prod
- запрет localhost DB/Redis в prod
- loud warning или hard-fail на `AUDIT_RETENTION_DAYS=0`
- warning или fail на `AUDIT_PAYLOAD_MODE=full` в prod

Acceptance criteria:

- процесс не стартует в заведомо небезопасной конфигурации
- ошибки конфигурации понятны оператору

#### 3. PR-D: Admin Access Audit

Цель: логировать чтение и изменение чувствительных admin-данных.

Скоуп:

- кто открывал `/audit/logs`
- кто открывал `/dashboard/*`
- кто запускал purge/erase/admin-only internal-db actions

Acceptance criteria:

- sensitive admin reads/actions попадают в отдельный admin event log
- есть минимальный search/filter path для расследования

#### 4. semantic_v2 shadow rollout

Цель: подтвердить benchmark на реальном трафике до enforce.

Скоуп:

- `FIREWALL_SA_V2_ENABLED=true`
- `FIREWALL_MODE_SEMANTIC_V2=shadow`
- same provider/model/corpus as benchmark baseline
- сбор FP/FN из real shadow hits

Gate:

- embedding fail/timeout rate ≈ 0
- FP на shadow hits приемлем
- alerts и runbooks реально проверены

---

## Roadmap 30-60 дней

### Must-Have for Signed Production

#### 5. Epic-1: Enterprise Auth

Цель: пройти enterprise security review по identity.

Скоуп:

- `OIDC` first
- `SAML` if target customers require it
- MFA для admin accounts
- migration path от локального auth к federated auth

Acceptance criteria:

- admin login можно вынести на enterprise IdP
- локальные admin аккаунты ограничены или контролируемы

#### 6. Epic-2: Tenant Isolation

Цель: сделать SaaS story защищаемой.

Скоуп:

- `tenant_id` в users, audit, policy, budget
- list/query/filter только в границах tenant
- retention и purge по tenant
- groundwork для per-tenant firewall/provider policy

Acceptance criteria:

- audit и dashboard не смешивают данные разных tenants
- purge/erasure можно запускать per-tenant

#### 7. Epic-3: Provider Governance

Цель: уметь отвечать на вопрос “куда уходят данные клиента и почему”.

Скоуп:

- approved provider set per tenant
- sensitivity-aware routing
- optional EU-only / region-pinned policy
- documented subprocessors and transfer mechanism

Acceptance criteria:

- tenant policy может запретить конкретные providers
- sensitive traffic можно ограничить approved provider subset

#### 8. Runbooks + Alerting

Цель: не только собирать метрики, но и реально отрабатывать инциденты.

Скоуп:

- alert → owner → action runbook
- incident severity mapping
- provider outage / embedding outage / audit queue growth runbooks
- breach/containment checklist

Acceptance criteria:

- на каждый критичный alert есть понятный action path
- можно провести dry-run tabletop

---

## Roadmap 60-90 дней

### Hardening for Broader GA

#### 9. PR-7: Stage 2 Streaming Passthrough

Цель: снять главный архитектурный blocker для “general hardened default”.

Скоуп:

- real streaming passthrough
- incremental enforcement
- bounded buffering only when needed
- no regression in budget/accounting path

Acceptance criteria:

- streaming не буферизуется целиком в обычном happy path
- enforcement остаётся корректным

#### 10. BYOK / KMS / Field-Level Encryption Hooks

Цель: подготовиться к требованиям regulated/enterprise клиентов.

Скоуп:

- design или optional implementation для шифрования audit-sensitive fields
- hooks под managed KMS
- optional BYOK roadmap

Acceptance criteria:

- есть технически понятный ответ на вопрос “как шифруются чувствительные данные?”

#### 11. Backup / Legal Hold / Restore Policy

Цель: согласовать retention, purge и backup reality.

Скоуп:

- documented backup retention
- restore testing
- legal hold policy
- interaction with DSAR / purge

Acceptance criteria:

- ops/legal понимают, что именно удаляется и что остаётся в backup cycle

#### 12. SOC 2 / ISO Readiness Track

Цель: подготовить evidence и control mapping.

Скоуп:

- controls inventory
- evidence collection process
- ownership
- mapping на текущие technical controls

Acceptance criteria:

- можно войти в formal readiness assessment без срочного переписывания продукта

---

## Что не делать прямо сейчас

- Не начинать `PR-7` до результатов `semantic_v2 shadow`.
- Не тюнить thresholds без real shadow data.
- Не тащить UI analytics раньше, чем появится operational pain.
- Не усложнять privacy model отдельными shadow-retention policy до явной бизнес-потребности.

---

## Что берём первым в работу

### Первый work item: PR-B — DSAR / Erasure Workflow

Причина выбора:

- это самый сильный remaining privacy/business blocker после `PR-A`
- он нужен раньше, чем tenant isolation и enterprise auth, если речь о реальных данных пользователей
- он даёт прямой ответ на вопрос бизнеса и legal: “как вы удаляете данные?”

### Предварительный scope PR-B

- admin-only `erase user data`
- удаление или необратимая анонимизация user profile
- анонимизация `audit_logs.user_id`
- policy для связанных audit fields и `shadow_decisions_json`
- admin event log на факт erasure
- docs/runbook для ops

### Предварительный DoD

- операция идемпотентна
- пользователь больше не восстанавливается из audit trail
- dashboard/audit не ломаются после erasure
- есть тесты на repeat execution и на отсутствие утечки связи с user

---

## Порядок исполнения

1. `PR-B` — DSAR / Erasure Workflow
2. `PR-C` — Prod Config Hardening
3. `PR-D` — Admin Access Audit
4. `semantic_v2` shadow rollout and observation
5. `Epic-1` — Enterprise Auth
6. `Epic-2` — Tenant Isolation
7. `Epic-3` — Provider Governance
8. `Runbooks + Alerting`
9. `PR-7` — Stage 2 Streaming Passthrough

---

## Decision Point

Текущий главный принцип:

- **до enterprise pilot:** privacy/governance first
- **до signed production:** identity + tenant isolation + provider governance
- **до broader GA:** Stage 2 streaming architecture

На сегодня первое, что берём в работу: **`PR-B: DSAR / Erasure Workflow`**.

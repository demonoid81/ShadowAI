# ShadowAI — Privacy / Retention / DSAR / Legal-Hold / Incident Runbook

**Версия документа:** 1.0
**Дата:** 2026-04-19
**Audience:** ops, compliance, legal, incident responders.
**Покрывает:** ShadowAI backend после merge PR-A/B/C/D/D.1.
**Jurisdiction baseline:** GDPR (EU). Короткие отличия для CCPA (US/CA)
вынесены в соответствующие разделы как `CCPA notes`.

> **Важно.** Документ явно разделяет:
>
> - **[implemented]** — реализовано в продукте, есть endpoint/CLI.
> - **[operational]** — manual процесс оператора, опирается на
>   implemented mechanisms.
> - **[manual]** — полностью ручное действие без автоматизации.
> - **[planned]** — roadmap, на сегодня отсутствует.
> - **[gap]** — known gap, не закрыт; нужно учитывать при принятии
>   compliance-обязательств.
>
> Если пункт не помечен как implemented, НЕ утверждайте в compliance-
> разговорах, что это "уже есть".

---

## 1. Purpose

Этот runbook — единый источник истины по privacy/retention/DSAR/
incident для ShadowAI. Его задача:

- описать, какие данные хранятся и как долго;
- дать чёткую процедуру DSAR/erasure для operator'а;
- явно перечислить известные gap'ы (особенно backup, legal hold);
- служить основой при incident response;
- быть базой для compliance-conversations (SOC 2, ISO 27001, GDPR
  Article 30 records).

Документ не заменяет Data Processing Agreement (DPA) с клиентами и
Privacy Policy, но является их operational backbone.

---

## 2. Data Inventory / Retention Matrix

Каждая строка — отдельный store или таблица. Implementation status
указывает, покрыто ли контролем автоматически или требует операторского
действия.

| Store | Contains | PII risk | Retention | Purge path | DSAR behavior | Legal hold | Status |
|---|---|---|---|---|---|---|---|
| `audit_logs` | user LLM-трафик (если `AUDIT_PAYLOAD_MODE=full`: raw request/response bodies; `redacted` — DLP-sanitized; `metadata` — только summary JSON; `none` — NULL). Metadata: user_id, model, provider, tokens, cost, pii flags, policy_action, shadow decisions. | Высокий (body) / Средний (metadata) | `AUDIT_RETENTION_DAYS` (default 0 = no purge). Prod override обязателен — `ValidateStartupConfig` требует либо retention>0, либо `AUDIT_ALLOW_NO_RETENTION_IN_PROD=true`. | `cmd/audit-purge --target audit_logs` или embedded scheduler (`AUDIT_PURGE_INTERVAL>0`). | **[implemented]** `ScrubUserDataTx` обнуляет `user_id`, `request_body`, `response_body`, `shadow_decisions_json`, `pii_types`. Остальные колонки (model/tokens/cost/policy_action/status_code/created_at) сохраняются для aggregate-аналитики. | **[gap]** автоматизации нет — см. §5. | **[implemented]** |
| `admin_event_logs` | admin reads (`/audit/logs`, `/dashboard/*`, `/audit/status`), `erase`, `purge`, internal-db admin CRUD. Metadata JSON — filters/counters; **НЕ содержит** raw bodies, SQL, DSN, secrets. | Низкий-средний (actor_user_id + action trail). | `ADMIN_AUDIT_RETENTION_DAYS` (default 0 = no purge). Отдельный scheduler. | `cmd/audit-purge --target admin_event_logs` или embedded scheduler. | **[gap]** DSAR `ScrubUserDataTx` НЕ трогает `admin_event_logs`. actor_user_id admin'а остаётся (FK `ON DELETE SET NULL` → превратится в NULL при удалении самого admin'а). Это сознательно: compliance-trail не должен ломаться при erasure одного из admin'ов. | **[gap]** manual. | **[implemented]** |
| `user_erasure_runs` | Tombstone-записи выполненных DSAR (target_user_id, initiated_by, counters, completed_at). | Низкий (только UUID'ы). | **Не purge'ится** (tombstone). | — | **[implemented]** — сама запись о erasure. target_user_id остаётся для идемпотентности. | **[implemented]** — сохраняется всегда. | **[implemented]** |
| `audit_purge_runs` | История purge-операций: target, cutoff, rows_deleted. | Минимальный (counters + timestamps). | **Не purge'ится** (short row, compliance evidence). | — | Не затрагивается. | Не затрагивается. | **[implemented]** |
| `users` | Аккаунты: email, bcrypt-password, role, API key hash, token_version. | Высокий (прямой PII). | Нет TTL — живут до явного erasure или deactivation. | `POST /api/users/{id}/erase` (admin-only). | **[implemented]** hard DELETE row в той же tx, что audit scrub. | **[gap]** manual: нужно блокировать erase endpoint для held user'а на application level. | **[implemented]** |
| `budgets` | User-scoped месячные лимиты и расходы. | Средний (привязан к user_id). | Нет TTL. | `POST /api/users/{id}/erase` удаляет row. | **[implemented]** DELETE в tx. | **[gap]** manual. | **[implemented]** |
| PostgreSQL backups | Full-DB snapshots. | Высокий (копия всех таблиц). | Определяется infra (не application). | N/A в коде. | **[gap]** backup НЕ purge'ится автоматически при DSAR. См. §4. | **[gap]** manual. | **[manual]** |
| Redis cache | Budget counters, semantic cache. | Низкий-средний. | `CACHE_TTL` (default 1h). | TTL-based eviction. | **[gap]** пока нет explicit flush по user_id при DSAR. **[planned]**. | — | **[gap]** |
| External LLM providers | OpenAI/Anthropic/Gemini/etc. логи запросов на их стороне. | Высокий. | Определяется DPA с провайдером. | **[gap]** не покрыт ShadowAI. | **[gap]** operator обязан отдельно запросить deletion через провайдера. | **[gap]** зависит от провайдера. | **[gap]** |
| Application logs (stdout) | Server logs (log.Printf). | Низкий (по контракту не содержат bodies, но warning'и могут). | Инфра (Loki/ELK/CloudWatch retention). | N/A. | **[gap]** не автоматизирован. | **[gap]** manual. | **[gap]** |
| Embedding corpus (`firewall_corpus/semantic_v2.json`) | Заготовленные known-attack embeddings. **НЕ** содержит user data. | Нет. | Регенерация оператором при изменении patterns. | `cmd/firewall-corpus-gen`. | Не затрагивается. | Не затрагивается. | **[implemented]** |

### CCPA notes

- CCPA требует отличать "sale/sharing" (у нас нет — ShadowAI не
  передаёт PII третьим сторонам) и "service providers" (внешние LLM
  провайдеры — технически service providers при правильных DPA).
- "Right to know" по CCPA: operator формирует ответ вручную из
  данных в `users` + aggregate из `audit_logs` (filter по `user_id`).
  **[manual]** — нет отдельного export API.
- SLA CCPA: 45 дней (vs 30 дней GDPR). При одновременном присутствии
  двух jurisdictions используется более строгий GDPR SLA.

---

## 3. DSAR / Erasure Procedure

### 3.1 Scope

DSAR-erasure в ShadowAI закрывает:
- удаление самой `users`-row (`[implemented]`);
- удаление `budgets` по user_id (`[implemented]`);
- обезличивание `audit_logs` (user_id + bodies + shadow + pii_types
  → NULL), сохраняя aggregate-метрики (`[implemented]`);
- запись tombstone в `user_erasure_runs` (`[implemented]`).

**Не закрывает автоматически:**
- backup snapshots (`[gap]`);
- external LLM provider logs (`[gap]`);
- application logs в stdout/Loki (`[gap]`);
- Redis-кеш (`[gap]`);
- `admin_event_logs`, где actor_user_id указывал на этого user'а
  (если он был admin'ом) — FK превратит его в NULL автоматически
  при DELETE row из `users`.

### 3.2 SLA

- **GDPR: 30 дней** с момента получения запроса до выполнения
  (с возможным продлением ещё на 60 дней для сложных случаев
  при уведомлении subject'а).
- **CCPA: 45 дней** (+45 с уведомлением).

При коллизии jurisdictions используется меньший срок (30 дней).

### 3.3 Кто может выполнить

- Только роль `admin` (enforced HTTP middleware на `/api/users/{id}/erase`).
  Non-admin → 403.
- **[operational]** Рекомендуется 4-eyes policy (approver + executor),
  но это процедурное — код её не enforce'ит. **[gap]** для автоматизации.

### 3.4 Endpoint

```
POST /api/users/{id}/erase
Authorization: Bearer <admin-JWT>
```

**Responses:**
- `200` + `{"status":"completed", "audit_rows_scrubbed":N, "budgets_deleted":M}` — ok.
- `200` + `{"status":"already_erased"}` — идемпотентный повтор (user
  уже erased, запись в `user_erasure_runs` есть).
- `404` + `{"status":"not_found"}` — user не существует и не был
  erased ранее.
- `403` — non-admin.
- `503` — erasure service не сконфигурирован (dev/misconfig).

Все исходы попадают в `admin_event_logs` с `action=erase, resource=user`
(`[implemented]` в `auth.Handler.EraseUser.recordErase`). `success=true`
для 2xx (включая `already_erased`); `false` для 4xx/5xx.

### 3.5 Operator checklist

1. **Identify**: получить user_id (GET `/api/users` с фильтром по
   email). Зафиксировать в ticket tracking (Jira/Linear).
2. **Approval** (`[operational]`): 4-eyes review если политика
   требует.
3. **Erase** (`[implemented]`):
   ```bash
   curl -X POST -H "Authorization: Bearer $ADMIN_JWT" \
     "$BACKEND_URL/api/users/$USER_ID/erase"
   ```
4. **Verify** (`[operational]`):
   ```sql
   -- user row deleted?
   SELECT id FROM users WHERE id = '$USER_ID';  -- no rows
   -- audit rows scrubbed?
   SELECT count(*) FROM audit_logs WHERE user_id = '$USER_ID'; -- 0
   -- tombstone recorded?
   SELECT * FROM user_erasure_runs WHERE target_user_id = '$USER_ID';
   -- admin event recorded?
   SELECT * FROM admin_event_logs
     WHERE action='erase' AND target_id='$USER_ID'
     ORDER BY created_at DESC LIMIT 1;
   ```
5. **Backup remediation** (`[manual]`): см. §4.3.
6. **External providers** (`[manual]`): отдельно submit deletion
   запросы в OpenAI/Anthropic (через их dashboards или support). DPA
   с провайдером должен покрывать этот SLA.
7. **Cache flush** (`[manual]` пока, `[planned]` automation):
   ```bash
   redis-cli --scan --pattern "budget:$USER_ID:*" | xargs redis-cli del
   redis-cli --scan --pattern "semantic_cache:*" | xargs -n 100 redis-cli del
   ```
   (semantic cache hash не привязан к user_id; precautionary flush).
8. **Document**: close ticket ссылкой на `user_erasure_runs.id`.
   Subject notification per DPA template.

### 3.6 Идемпотентность

`already_erased` — штатный исход повторного запроса (PR-D fix).
Operator может безопасно re-run команду в любое время; new
`user_erasure_runs` row не создаётся, `admin_event_logs`
фиксирует попытку с `success=true` и `status=already_erased`.

---

## 4. Backup / Restore Policy

### 4.1 Что входит в backup

PostgreSQL dump содержит **все** таблицы: `users`, `audit_logs`,
`admin_event_logs`, `user_erasure_runs`, `audit_purge_runs`,
`budgets`, `policies`, etc. — включая любые row'ы, созданные
до последнего DSAR.

**[gap]** Backup snapshots не интегрированы с DSAR/purge flow.

### 4.2 Рекомендованный retention для backups

Два обязательных инварианта:

1. **Backup retention ≤ наименьшего application retention.** Если
   `AUDIT_RETENTION_DAYS=30` и backup retention=90, rolling backup
   содержит данные младше 30 дней в product но 31-90 дней в copy →
   DSAR не завершается полностью за этот период.
2. **Rolling eviction fully covers DSAR SLA.** Если SLA=30 дней
   (GDPR), все backups старше 30 дней должны быть автоматически
   удалены, чтобы erased user исчез из всех snapshots к моменту
   SLA expiration.

**Рекомендация:** backup retention ≤ 30 дней (rolling daily, 30-day
window). Если compliance требует больших retention — см. §4.4
("selective scrubbing") или явное исключение в legal hold.

### 4.3 Восстановление из backup: erased user вернулся

Если ops-команда восстановила DB из snapshot'а, сделанного **до**
DSAR-erasure конкретного user'а, то:

1. Появятся back'ом row'ы в `users`, `budgets`; `audit_logs` row'ы
   с plain PII.
2. **`user_erasure_runs` tombstone сохранится** (если snapshot свежее
   чем самый старый DSAR) → повторный `POST /users/{id}/erase`
   вернёт `already_erased` и **не** пере-scrub'нёт audit rows.
3. **Remediation (`[manual]`):**
   ```sql
   -- identify all erased user IDs из tombstone
   SELECT target_user_id FROM user_erasure_runs;
   ```
   Для каждого:
   ```sql
   -- manual re-scrub (копия логики ScrubUserDataTx)
   UPDATE audit_logs SET
     user_id=NULL, request_body=NULL, response_body=NULL,
     shadow_decisions_json=NULL, pii_types=NULL
     WHERE user_id='$TARGET_USER_ID';
   DELETE FROM budgets WHERE user_id='$TARGET_USER_ID';
   DELETE FROM users WHERE id='$TARGET_USER_ID';
   ```
4. **Document restore**: запись в ops-ticket с timestamp snapshot'а и
   списком re-eras'ed user_id'ов.

### 4.4 Selective scrubbing для long-retention backups

Если compliance обязывает хранить backup'ы дольше DSAR SLA (редкий
случай, обычно финансовая/таможенная отчётность), варианты:

- **[planned]** автоматический post-restore hook, прогоняющий
  `ScrubUserDataTx` по всем tombstones;
- **[manual]** периодическая "scrub pass" по старым backup'ам
  (expensive).

Ни один из подходов на 2026-04-19 не продуктизирован.

### 4.5 CCPA notes

CCPA не требует удаления из backups немедленно, но предполагает
"commercially reasonable" процесс. Документируйте ваше backup retention
в Privacy Policy как material fact.

---

## 5. Legal Hold

### 5.1 Что это

Requirement "заморозить" удаление данных конкретного user'а / query'а /
временного окна в случае litigation, investigation, regulatory probe.
Отменяет стандартный DSAR и retention TTL.

### 5.2 Implementation status

**[gap]** Автоматизация отсутствует. ShadowAI не имеет:
- flag'а `legal_hold` на user-row'е;
- интерсепта в `ScrubUserDataTx` / `PurgeOlderThan`;
- dedicated `legal_holds` таблицы.

### 5.3 Manual процедура (рекомендованная)

1. **Trigger**: legal/compliance получает hold-order. Фиксируется в
   external system (ticket tracker, legal CMS).
2. **Application-level block**:
   - **[manual]** operator явно приостанавливает `cmd/audit-purge`
     scheduler (`AUDIT_PURGE_INTERVAL=0` + restart).
   - **[manual]** для конкретного user: перед DSAR operator проверяет
     hold-registry (external); если user held — **отказывает в erase**
     с HTTP 409/503 на operational level (сам endpoint код сейчас не
     enforce'ит — admin обязан не запускать команду).
3. **Backup freeze** (`[manual]`): infra-команда исключает snapshot'ы,
   covered hold'ом, из rolling eviction.
4. **Release**: когда hold снят, возобновить scheduler; при
   необходимости запустить накопленный DSAR.

### 5.4 Конфликт DSAR vs Legal Hold

**Приоритет: Legal Hold > DSAR.** GDPR Article 17(3)(e) явно даёт
исключение для "establishment, exercise, or defence of legal claims".

В ShadowAI:
- [manual] operator должен проверять hold-статус **ДО** запуска
  `/users/{id}/erase`.
- Если пропустил — DSAR выполнится (код не enforce'ит); remediation
  ограничен, т.к. erasure hard (`budgets` DELETE необратим без backup).

### 5.5 Planned improvements

**[planned]** В roadmap:
- таблица `legal_holds` (target_user_id, reason, active, created_by).
- `ScrubUserDataTx` проверяет активный hold; отказывает с явной
  ошибкой.
- `/users/{id}/erase` — 409 если user held.
- `admin_event_logs` фиксирует attempts на held user'ах.

Пока не реализовано — процедура в §5.3 обязательна.

---

## 6. Incident / Breach Workflow

### 6.1 Detect

Источники сигналов:
- Prometheus alerts на `shadowai_audit_dropped_total`,
  `shadowai_embedding_fail_total`, `shadowai_judge_timeout_total`
  (технические).
- Ручной audit `/api/admin-events` (unusual read patterns).
- External (customer report, security researcher).

### 6.2 Contain

1. **Rotate credentials** (`[operational]`):
   - `JWT_SECRET` → новый, всем выданным токенам наступает end-of-life
     после `token_version++` per user (`RevokeTokens` endpoint) или
     полного restart'а.
   - All `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / etc. — rotate в
     соответствующих vendor dashboards.
   - `DATABASE_URL` password — rotate если скомпрометирован.
2. **Disable affected endpoints** (`[manual]`): временный block в
   middleware или config-flag (нет готового feature-flag system на
   2026-04-19).
3. **Preserve evidence**: **[manual]** немедленный backup БД (даже
   если это ломает backup rotation). Не запускать `audit-purge` до
   end-of-investigation.

### 6.3 Notify

GDPR: 72 часа на уведомление supervisory authority (Article 33) для
breach, который "likely to result in a risk" для subject'ов. Отдельно
— subject notification без "undue delay" при "high risk" (Article 34).

CCPA: без жёсткого SLA на regulator notification, но Attorney General
требует уведомления при `>500` CA residents affected.

**[manual]** Legal/compliance team issue'ит notifications через
предварительно согласованные templates.

### 6.4 Forensics

`admin_event_logs` — ключевой источник. SQL-шаблоны:

```sql
-- Кто читал audit за последние N дней
SELECT actor_user_id, COUNT(*), MAX(created_at)
FROM admin_event_logs
WHERE action='read' AND resource IN ('audit_logs','audit_status','dashboard')
  AND created_at > now() - interval '7 days'
GROUP BY actor_user_id
ORDER BY COUNT(*) DESC;

-- Все действия конкретного admin'а
SELECT * FROM admin_event_logs
WHERE actor_user_id='<id>'
ORDER BY created_at DESC;

-- Подозрительные erase
SELECT * FROM admin_event_logs
WHERE action='erase'
  AND created_at > now() - interval '30 days';
```

**[gap]** `admin_event_logs` НЕ immutable — admin с DB-доступом
может UPDATE/DELETE напрямую. Compliance-grade WORM требует внешнего
SIEM (Splunk/Elastic/Datadog) с tamper-evident storage.

### 6.5 Remediate

1. Root cause analysis (RCA): что именно дало attacker'у доступ?
2. Patch + deploy.
3. Post-incident review: что в privacy-контракте упало? Обновить этот
   runbook в разделе §8 Known Gaps.

---

## 7. Operator Quick Reference

### 7.1 Выполнить DSAR erasure

```bash
# Find user
curl -sH "Authorization: Bearer $ADMIN_JWT" \
  "$URL/api/users" | jq '.[] | select(.email=="target@example.com")'

# Erase
curl -sX POST -H "Authorization: Bearer $ADMIN_JWT" \
  "$URL/api/users/$USER_ID/erase" | jq

# Verify tombstone
curl -sH "Authorization: Bearer $ADMIN_JWT" \
  "$URL/api/admin-events?action=erase&resource=user&limit=5" | jq
```

### 7.2 Проверить retention config

```bash
curl -sH "Authorization: Bearer $ADMIN_JWT" "$URL/api/audit/status" | jq
# Показывает: payload_mode, retention_days, scheduler_enabled,
# last_purged_at, rows_purged_total — для audit_logs + admin_events.
```

### 7.3 Найти кто читал audit за неделю

```bash
curl -sH "Authorization: Bearer $ADMIN_JWT" \
  "$URL/api/admin-events?resource=audit_logs&action=read&limit=200" | jq \
  '.data | group_by(.actor_user_id) | map({actor: .[0].actor_user_id, count: length})'
```

### 7.4 Проверить последние purge runs

```sql
-- из DB (admin-доступ)
SELECT target, COUNT(*), MAX(completed_at), SUM(rows_deleted)
FROM audit_purge_runs
WHERE completed_at > now() - interval '30 days'
GROUP BY target;
```

### 7.5 Ручной purge (если scheduler disabled)

```bash
# audit_logs
./audit-purge --retention-days 30 --target audit_logs

# admin_event_logs
./audit-purge --retention-days 365 --target admin_event_logs

# dry-run (count, no delete)
./audit-purge --retention-days 30 --target audit_logs --dry-run
```

### 7.6 Список active user_erasure_runs tombstones

```sql
SELECT target_user_id, completed_at, audit_rows_scrubbed, budgets_deleted
FROM user_erasure_runs
ORDER BY completed_at DESC
LIMIT 50;
```

---

## 8. Known Gaps

Каждый пункт — потенциальный compliance-риск или блокер для SOC 2/
ISO 27001 certification. Решение требует дополнительных PR либо
external tooling.

### 8.1 Backup lifecycle

- **[gap]** Backup retention не синхронизирован с
  `AUDIT_RETENTION_DAYS` автоматически.
- **[gap]** Post-restore hook для повторного scrub'а erased user'ов
  отсутствует. Remediation в §4.3 — ручной SQL.
- **[planned]** `cmd/backup-postrestore-scrub` CLI.

### 8.2 Legal hold

- **[gap]** Flag `legal_hold` на user-row'ах отсутствует.
- **[gap]** `ScrubUserDataTx` не проверяет hold-registry.
- **[gap]** Нет endpoint'а `/api/legal-holds` CRUD.
- **[planned]** таблица `legal_holds` + интерсепт в erase flow
  (см. §5.5).

### 8.3 External storage erasure

- **[gap]** Redis cache: нет explicit flush по user_id при DSAR.
- **[gap]** Application logs в stdout/Loki не обработаны.
- **[gap]** External LLM providers (OpenAI/Anthropic/etc.): нет
  программного mirror-DSAR call. Operator делает вручную через
  vendor support/dashboard.
- **[planned]** DSAR-hooks которые отправляют deletion requests в
  сторонние системы.

### 8.4 Tamper-evident admin audit

- **[gap]** `admin_event_logs` хранится в primary PG, admin с DB-
  доступом может редактировать напрямую. Это нарушает "immutability"
  которую ожидает compliance-grade WORM.
- **[implemented]** Mirror в external SIEM через HTTP (Splunk HEC,
  Elastic ingest, custom collector). `SIEM_ENABLED=true` +
  `SIEM_ENDPOINT=https://...` + опциональный `SIEM_BEARER_TOKEN`
  активируют fan-out: каждая запись в `admin_event_logs` дублируется
  в HTTP sink. Fail-open: недоступность SIEM не ломает primary
  endpoint; PG остаётся source of truth. Реализовано в
  `backend/internal/siem/` (PR-S1). Metrics:
  `shadowai_siem_requests_total`, `_fail_total`, `_timeout_total`,
  `_latency_seconds`.
- **[planned]** full WORM-storage (primary storage is external
  append-only, а не PG) — v2+ ask; требует external-first write
  architecture.

### 8.5 Access audit для user reads

- **[implemented]** GET `/api/users/{id}` → запись в `admin_event_logs`
  (resource=`user`, action=`read`, target_id=`{id}`). Metadata
  включает `target_role`; email НЕ дублируется (сам endpoint
  возвращает email — запись о доступе достаточна для forensics).
  Реализовано в `authHandler.recordUserRead` (PR-G0).
- **[implemented]** GET `/api/users` (ListUsers) → запись в
  `admin_event_logs` (resource=`users` plural, action=`list`,
  target_id пустой). Metadata ограничена `user_count`; emails/role'ы
  клиентов не дублируются (response body уже их содержит). Failure
  path (repo error → 500) тоже пишет event с `success=false`.
  Реализовано в `authHandler.recordUsersList` (PR-G0.1).
- **[implemented]** PUT `/api/users/{id}` (UpdateUser) → запись в
  `admin_event_logs` (resource=`user`, action=`update`,
  target_id=`{id}`). Metadata содержит diff: `changed_fields`
  (подмножество из `email`, `role`, `is_active`), а также `old_*`/
  `new_*` значения для `role` и `is_active`. Для email пишется
  только флаг `email_changed: true/false` (raw email-адрес в
  metadata запрещён privacy-контрактом). Failure paths (404 user
  not found, 400 invalid JSON/role, 500 repo error) тоже пишут
  event с `success=false`. Реализовано в
  `authHandler.recordUserUpdate` (PR-G0.2).

### 8.6 4-eyes policy для destructive ops

- **[gap]** `POST /users/{id}/erase` executes immediately без
  approver workflow.
- **[planned]** `pending_erasures` таблица + approver endpoint.

### 8.7 CCPA "right to know" export

- **[gap]** Нет API для экспорта данных одного user'а.
- **[operational]** formируется вручную SQL+ETL.
- **[planned]** `GET /api/users/{id}/export` с machine-readable
  portability bundle (Article 20 GDPR / CCPA 1798.110).

### 8.8 Tenant isolation

- **[gap]** Single-tenant модель (нет `tenant_id` на user/audit/
  admin_event_logs).
- **[planned]** PR-F (roadmap) если проект идёт в multi-tenant SaaS.
  До этого — deploy'ить отдельные инстансы per tenant.

### 8.9 SCIM / SSO

- **[gap]** User CRUD только через `/api/auth/register` (admin-driven)
  или self-register если enabled.
- **[gap]** Нет SCIM 2.0 endpoint для provisioning от IdP.
- **[planned]** enterprise roadmap.

### 8.10 Automated privacy impact assessment (PIA / DPIA)

- **[gap]** Нет инструментов отслеживать, какие новые feature'ы
  влияют на PII flow.
- **[operational]** review process на уровне PR-template (каждый
  privacy-touching PR требует явного раздела в описании).

---

## 9. Change log

- **1.4 (2026-04-22)** — PR-S1: §8.4 дополнен SIEM mirror для
  `admin_event_logs` через HTTP (fail-open). Закрывает основной
  ask для external tamper-resistant log pipeline. WORM primary
  storage остаётся v2+ roadmap.
- **1.3 (2026-04-22)** — PR-G0.2: §8.5 дополнен UpdateUser audit.
  `authHandler.recordUserUpdate` пишет `admin_event_logs` с
  `resource=user, action=update` + diff в metadata (changed_fields,
  old/new для role/is_active, email_changed flag). Закрыт весь
  admin user-governance trail (read / list / update / erase).
- **1.2 (2026-04-22)** — PR-G0.1: §8.5 дополнен ListUsers audit.
  `authHandler.recordUsersList` пишет admin_event_logs с
  `resource=users, action=list`. UpdateUser остаётся `[gap]` (PR-G0.2).
- **1.1 (2026-04-21)** — PR-G0: §8.5 user-read access audit переведён
  в `[implemented]` для GET `/api/users/{id}`. ListUsers/UpdateUser
  остаются `[gap]` (PR-G0.1/G0.2).
- **1.0 (2026-04-19)** — начальная версия, покрывает PR-A/B/C/D/D.1.
  Известные gaps §8 явно перечислены.

---

## 10. Contacts & escalation

- **Privacy / DPO**: `<fill-in>`.
- **Security team**: `<fill-in>`.
- **On-call engineer**: `<fill-in>`.

> Эти поля — обязательные при prod-развёртывании. Без конкретных
> имён/email'ов этот runbook не может считаться operational. Обновлять
> при ротации ролей.

---

## 11. How to update this document

1. Каждый PR, затрагивающий privacy/audit/retention/DSAR, должен
   включать раздел "Runbook impact" в описании.
2. Если статус сдвигается с `[manual]` / `[planned]` на
   `[implemented]` — обновите соответствующую строку в §2 Retention
   Matrix и §8 Known Gaps.
3. Version number в header увеличивается при material изменениях.
4. Change log (§9) — append-only.

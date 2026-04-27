# ShadowAI — Privacy / Retention / DSAR / Legal-Hold / Incident Runbook

**Версия документа:** 1.20
**Дата:** 2026-04-27
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

**[implemented]** PR-L1 + PR-L2.3: автоматизация per-user legal
holds с 4-eyes approver workflow.
- Таблицы:
  - `legal_holds` (migration
    `backend/migrations-enterprise/013_create_legal_holds.sql`).
  - PR-L2.3: `legal_holds.status` column + `approved_at/by`
    (migration `015_legal_hold_status_four_eyes.sql`). Статусы:
    `pending | active | released`.
- Admin-only endpoints:
  - `POST /api/legal-holds` — создать **pending** hold. Ещё НЕ
    блокирует DSAR и НЕ защищает audit от purge. 409 если у
    user'а уже есть blocking (pending OR active) hold.
  - `POST /api/legal-holds/{id}/approve` — **4-eyes approval**:
    pending → active. Approver должен отличаться от creator;
    self-approval → 403 + admin event с `error_code=self_approval`
    (SIEM-alerting key).
  - `POST /api/legal-holds/{id}/reject` — pending → released
    (cancel). Rejector может совпадать с creator (cancel собственного
    request'а).
  - `POST /api/legal-holds/{id}/release` — active → released
    (идемпотентно, на pending возвращает 409).
  - `GET /api/legal-holds` — list (active + pending + released
    история). admin event metadata содержит `active_count` и
    `pending_count`.
- `ErasureService.EraseUser` делает pre-tx `HasActiveHold` check.
  Только `status = 'active'` блокирует — pending hold НЕ блокирует
  DSAR. Fail-closed при `legal_holds` DB error.
- Admin audit events:
  - `apply_hold_requested` — create (pending).
  - `apply_hold_approved`  — approve (pending → active). 4-eyes
    violation (self-approval) → success=false +
    `metadata.error_code=self_approval`.
  - `apply_hold_rejected`  — reject (pending → released).
  - `release_hold`         — release (active → released).
  - `read`                 — list.
  Все events mirror'ятся в SIEM (PR-S1).
- PR-L7 добавляет operational signals:
  - `legal_hold_sla_breached` — scheduler-событие, если hold слишком
    долго находится в `pending` или `release_pending`.
  - `dsar_blocked_by_legal_hold` — DPO-facing сигнал, если DSAR
    заблокирован active/release-pending legal hold.
  Оба сигнала пишутся в `admin_event_logs`, mirror'ятся в SIEM и
  имеют Prometheus alerts.

**[breaking, SIEM]** PR-L2.3 переименовал `action=apply_hold` →
`apply_hold_requested`. SIEM-rules и дашборды, которые matched
`apply_hold` exact, должны быть обновлены. Error code на dup
conflict: `already_active` → `already_blocking`. Changelog 1.17
фиксирует migration path.

**[gap] / [operational]** Что осталось вне scope или требует внешней
интеграции:
- Backup-freeze — infra-уровня, остаётся manual.
- Hold-scope шире date-range (query-window/query-scope hold) —
  roadmap. Date-range enforcement реализован в L6.
- External email/webhook/ticket-routing на основе L7 SLA/DPO signals —
  operator-owned integration.
- Bulk approvals/rejections реализованы в L5; UI для них остаётся out of scope.
- UI beyond minimal API — roadmap.

### 5.3 Operator процедура (PR-L1 + PR-L2.3)

**Важно (PR-L2.3)**: legal hold становится effective (блокирует
DSAR и защищает audit от purge) ТОЛЬКО после второго approve.
Шаг "apply" теперь создаёт только request — требуется independent
review.

1. **Trigger**: legal/compliance получает hold-order, фиксируют
   внешнее дело/запрос (ticket, subpoena ID).
2. **Step 1 — Request hold (creator admin)**:
   ```bash
   curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN_CREATOR" \
     -H "Content-Type: application/json" \
     -d '{"target_user_id":"u-target",
          "case_ref":"SEC-2026-042",
          "reason":"SEC inquiry, see ticket LEGAL-137"}' \
     https://shadowai.example/api/legal-holds
   ```
   Response 201 с `id` и `status:"pending"`. Event
   `apply_hold_requested` + mirror в SIEM. На этом этапе hold
   НЕ блокирует DSAR.
3. **Step 2 — 4-eyes approval (другой admin)**:
   ```bash
   curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN_APPROVER" \
     https://shadowai.example/api/legal-holds/{id}/approve
   ```
   Approver должен отличаться от creator. Response 200 с
   `status:"active"`. Event `apply_hold_approved`. С этого
   момента hold effective.

   Если approver == creator → 403 + event
   `apply_hold_approved` с `success=false` и
   `metadata.error_code=self_approval` (критичный SIEM-alert).

4. **(Optional) — Cancel pending request**:
   ```bash
   curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
     https://shadowai.example/api/legal-holds/{id}/reject
   ```
   Переводит pending → released (cancelled). Event
   `apply_hold_rejected`. Допустимо creator'у (это отмена
   собственного request'а, НЕ approval).

5. **DSAR attempts блокируются автоматически** (только после
   approve): запрос `POST /api/users/{id}/erase` на held user
   вернёт 409 + `{status:"hold_active"}`. Admin event `erase` +
   metadata `blocked_by_hold=true`.
4. **Backup freeze** (`[manual]`): infra excludes snapshot'ы с
   held data из eviction.
5. **Audit-retention**:
   - **Enterprise build + scheduler** (`[implemented]`,
     PR-L3): in-process scheduler использует coordinated
     `PurgeOlderThanRespectingHoldsAndRecordRun`. Apply_hold и
     purge берут shared `pg_advisory_xact_lock`. Commit-order
     guarantee: если apply_hold commit раньше purge commit —
     rows защищены. Если apply_hold позже — rows того tick'а
     уже удалены (допустимо: hold не существовал в момент
     purge).
   - **Manual pause НЕ требуется** для enterprise scheduler'а.
   - **Core-only CLI** (`cmd/audit-purge` без enterprise tag
     или внешний cron-wrapper вокруг CLI): `[manual]`. CLI не
     консультирует legal_holds (Core scope без enterprise
     таблицы) и не участвует в advisory lock coordination.
     Operator обязан остановить CLI-cron / установить
     `AUDIT_PURGE_INTERVAL=0` на время hold'а либо
     предоставить собственный exclusion-wrapper вокруг
     `PurgeOlderThanExcept`.
6. **Release** (active → released):
   ```bash
   curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
     https://shadowai.example/api/legal-holds/{id}/release
   ```
   200 + body с `status:"released", is_active=false,
   released_at, released_by`. Event `release_hold`. После release
   DSAR на этого user'а работает штатно.

   **Release на pending** возвращает **409** с
   `{"error":"hold is pending, use reject to cancel"}` и admin
   event `metadata.error_code="pending_not_releasable"`. НЕ
   трактуется как идемпотентный успех — для отмены pending
   используйте `/reject`. Идемпотентность Release сохраняется
   только для "уже released" (active → released двойной вызов → 200
   `already_released`).

### 5.4 Конфликт DSAR vs Legal Hold

**Приоритет: Legal Hold > DSAR.** GDPR Article 17(3)(b)/(c)/(e)
прямо даёт carve-out для legal obligations и защиты claims.

В ShadowAI (PR-L1): enforcement работает на application-level.
`/users/{id}/erase` отвергается с 409 до начала транзакции.
Попытка записывается в `admin_event_logs` → SIEM mirror. Operator
обязан **не исполнять** erasure вручную через DB в обход endpoint —
это нарушает audit trail.

<a id="legal-hold-sla"></a>

### 5.5 Legal Hold SLA Signals (PR-L7)

**[implemented]** Scheduler периодически сканирует legal holds и
пишет `admin_event_logs` event `action=legal_hold_sla_breached`,
если:

- `status=pending` старше `LEGAL_HOLD_PENDING_SLA_HOURS`;
- `status=release_pending` и `release_requested_at` старше
  `LEGAL_HOLD_RELEASE_PENDING_SLA_HOURS`.

Сигнал dedupe'ится по hold/status/UTC-day через metadata
`dedupe_bucket`, чтобы Prometheus/SIEM не получали бесконечный spam
для одного и того же hold. Scheduler настраивается:

- `LEGAL_HOLD_PENDING_SLA_HOURS` — default `24`;
- `LEGAL_HOLD_RELEASE_PENDING_SLA_HOURS` — default `24`;
- `LEGAL_HOLD_SLA_SCAN_INTERVAL` — default `1h`.

Prometheus signals:

- `shadowai_legal_hold_sla_breaches_total{status="pending"}`;
- `shadowai_legal_hold_sla_breaches_total{status="release_pending"}`;
- `shadowai_legal_hold_sla_oldest_age_hours{status="..."}`.

Operator action:

1. Найти hold по `target_id` в alert/admin event.
2. Проверить `metadata.status`, `age_hours`, `threshold_hours`.
3. Для `pending` — назначить независимого approver'а или reject.
4. Для `release_pending` — approve/reject release request.
5. Зафиксировать external legal ticket / DPO case reference вручную,
   если организация требует case-management outside ShadowAI.

<a id="dsar-blocked-by-legal-hold"></a>

### 5.6 DSAR Blocked By Legal Hold Signal (PR-L7)

**[implemented]** Если `POST /api/users/{id}/erase` возвращает 409 из-за
active или release-pending legal hold, handler дополнительно пишет
`admin_event_logs` event:

- `action=dsar_blocked_by_legal_hold`;
- `resource=dsar`;
- `status_code=409`;
- metadata: `event_code`, `status`, `target_org_id`,
  `notification_type=dpo_signal`.

Метрика:

- `shadowai_dsar_dpo_signal_total{result="blocked_by_hold"}`.

Это не отправляет email напрямую. Сигнал предназначен для SIEM,
Prometheus alerting и downstream workflow engine, который уведомляет
DPO/legal team по локальным правилам организации.

### 5.7 Planned improvements (v2+)

- Hold-scope шире: per-query, per-conversation. Per-date-range enforcement
  реализован в L6.
- 4-eyes workflow для release реализован в L5.
- External SLA routing — email/webhook/ticket creation на основе L7
  admin/SIEM/Prometheus signals.
- Bulk approvals — approve нескольких pending за один call.
- Auto-release по external signal (webhook от legal CMS).
- UI для approver queue (на сейчас — только API).

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

- **[implemented]** таблица `legal_holds` (migration 013),
  application-layer enforcement в `ErasureService.EraseUser`
  pre-tx (см. §5). Admin CRUD: `POST /api/legal-holds`,
  `POST /api/legal-holds/{id}/release`, `GET /api/legal-holds`.
  Attempted-blocked erasures — `admin_event_logs` с
  `metadata.blocked_by_hold=true`.
- **[implemented]** (PR-L1.2) case_ref токен для SIEM-mirror —
  keyed HMAC-SHA256 (`LEGAL_HOLD_TOKEN_SECRET` обязателен в prod,
  `ValidateStartupConfig` требует >=32 chars). Без secret
  guessable case-IDs (SEC-2026-NNN) можно было бы brute-force'ить
  из mirror dump.
- **[implemented]** (PR-L2 → PR-L2.2 → **PR-L3**)
  Retention-aware audit purge с coordination-based race closure
  для enterprise `runAuditPurgeScheduler`:
  - **Commit-order guarantee**: и `apply_hold`, и coordinated
    purge берут shared `pg_advisory_xact_lock(4201, 1)` внутри
    своих tx. Если `apply_hold` закоммитился раньше purge-commit'а,
    purge не может удалить audit_logs этого user'а. Если
    purge закоммитился раньше apply_hold — удаление допустимо
    (hold ещё не существовал на момент purge-commit'а).
  - **Atomic purge+record**: `PurgeOlderThanRespectingHoldsAndRecordRun`
    делает DELETE + INSERT into `audit_purge_runs` в одной tx
    под тем же lock'ом. RecordPurgeRun больше не вызывается
    scheduler'ом отдельно.
  - **Fail-closed**: ошибка begin-tx / lock / delete / record
    → rollback, purge-tick не засчитывается, admin-event +
    SIEM mirror.
  - `holds_excluded` snapshot count остаётся в admin_event_logs
    для forensic display (race в count acceptable, correctness
    уже защищена lock'ом).
  - **НЕ гарантия "magically по времени начала запроса"**:
    если apply_hold начат ПОСЛЕ purge-commit'а, его rows на
    том tick'е уже удалены. Operator mitigation: apply_hold
    сразу при получении hold-order — любые rows по user'у,
    которые на этот момент существуют в audit_logs, защищены
    на всех следующих tick'ах.
  - **Core-only CLI** `cmd/audit-purge` в coordination НЕ
    участвует (Core scope не имеет legal_holds) — остаётся
    `[manual]`.
- **[gap]** Core-only build'а `cmd/audit-purge` CLI не имеет
  доступа к legal_holds (package enterprise-only) — использует
  backward-compat `PurgeOlderThan`. Для Core operator ожидается
  чисто manual retention без legal-hold'ов.
- **[implemented]** (PR-L2.3) 4-eyes approver workflow для apply
  hold: create делает pending, второй admin делает approve →
  active. Self-approval блокируется на repo-layer + handler
  возвращает 403 с `metadata.error_code=self_approval`
  (SIEM-alerting key). См. §5.2 / §5.3.
- **[implemented]** 4-eyes для release — L5.
- **[implemented]** Date-range hold enforcement — L6.
- **[gap]** Hold-scope шире date-range (query-window/query-scope) —
  v2+ roadmap.
- **[implemented]** SLA / DPO signals для legal hold и DSAR block —
  L7, см. §5.5 / §5.6. External email/webhook/ticket-routing
  остаются operator-owned integration.

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
- **[implemented]** Prod startup-guards (PR-S1.1): `ValidateStartupConfig`
  отвергает небезопасные SIEM-конфигурации в prod:
  - `SIEM_ENABLED=true` с пустым `SIEM_ENDPOINT` — rejected
    (misleading: operator думает что mirror работает, но ничего
    не отправляется);
  - `SIEM_ENDPOINT` без схемы `https://` — rejected (evidence
    stream требует in-transit encryption);
  - `SIEM_INSECURE_SKIP_VERIFY=true` без explicit
    `SIEM_ALLOW_INSECURE_IN_PROD=true` — rejected (TLS bypass
    допустим только при осознанном override: internal CA, kill-switch
    во время incident).
  Dev/staging env игнорирует эти правила (`IsProduction()` → false).
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

- **1.20 (2026-04-27)** — PR-L7: legal hold SLA и DPO-facing
  signals. Scheduler пишет `legal_hold_sla_breached` для
  `pending` / `release_pending` holds старше настроенных порогов.
  DSAR block из-за active/release-pending hold пишет
  `dsar_blocked_by_legal_hold`. Оба события попадают в
  `admin_event_logs`, SIEM mirror и Prometheus. External email,
  webhook и ticket-routing остаются operator-owned integration.
- **1.19 (2026-04-23)** — PR-F7.3: structured streaming audit outcomes.
  Migration `backend/migrations/009_add_streaming_audit_outcomes.sql`
  добавляет 3 колонки в `audit_logs`: `outcome`, `fallback_reason`,
  `usage_source`. Compound marker hack из F7.2.1
  (`streaming_buffered_fallback:<x>` в `policy_action`) строго
  удалён.
  **Breaking changes (synchronous dashboard/SIEM rollout):**
  - `policy_action` больше не содержит transport/accounting
    семантики; возвращается к чистым verdict'ам (allowed/blocked/
    flagged/sanitized).
  - Старые F7.1/F7.2 значения в `policy_action`
    (`streaming_transport_error`, `streaming_flagged`,
    `streaming_blocked_midflight`, `streaming_buffered_fallback`,
    `streaming_budget_exceeded_soft`) переехали в `outcome` как
    `stream_transport_error` / `stream_flagged` / etc.
  - Новый outcome `stream_blocked` (без `_midflight` суффикса) для
    buffered-path блока (stream machinery была invoked, client
    получил 403 до emit'а).
  - Compound marker `streaming_buffered_fallback:<x>` убран полностью.
  - SIEM JSON получает 3 новых поля (`outcome`, `fallback_reason`,
    `usage_source`) с `omitempty` — legacy записи без них.
  Dashboards должны матчить `outcome` вместо `HasPrefix(policy_action,
  "streaming_")`.
- **1.18 (2026-04-22)** — PR-L2.3.1 follow-up по ревью:
  - Release на pending перестал collapse'иться в 200
    `already_released`. Новый sentinel `ErrPendingNotReleasable`
    (отличный от `ErrNotActive`) → handler возвращает 409
    `pending_not_releasable` с подсказкой использовать `/reject`.
    Admin event пишется `success=false`, что защищает audit-trail
    от ложного "successful release" на pending.
  - §8.2 — убран stale gap "4-eyes approver workflow не
    реализован"; запись переведена в `[implemented]` с указанием
    на §5.2/§5.3. Добавлены явные gap'ы для release-4-eyes, SLA
    escalation, bulk approvals.
- **1.17 (2026-04-22)** — PR-L2.3: 4-eyes approver workflow для legal
  hold. Migration 015 добавляет `legal_holds.status` (pending /
  active / released) + `approved_at/by`. Partial-unique index
  расширен до `pending OR active` per user. Новые endpoints:
  `POST /api/legal-holds/{id}/approve` (4-eyes, approver != creator
  → 403 self_approval) и `.../reject` (cancel pending).
  **Breaking (SIEM):** admin event action `apply_hold` переименован
  в `apply_hold_requested` (на create) + добавлены
  `apply_hold_approved` / `apply_hold_rejected`; error_code
  `already_active` → `already_blocking`. Pending hold НЕ блокирует
  DSAR и НЕ защищает audit от purge — только approve'нутый делает
  hold effective. Retention-aware purge (`audit/retention_hold.go`)
  переключён на `status = 'active'` вместо `is_active=true` (sync'ы
  сохраняются по migration).
- **1.16 (2026-04-22)** — PR-L4: PostgreSQL integration harness
  (testcontainers-go) для PR-L3 commit-order proof. Новый пакет
  `backend/integration/` под `//go:build enterprise && integration`.
  3 concurrency scenarios (hold-before-purge / purge-before-hold /
  mixed-users) детерминистично воспроизводимы и passing. Обычный
  `go test ./...` не требует Docker.
- **1.15 (2026-04-22)** — PR-L3: coordination-based race closure.
  apply_hold и retention-aware purge синхронизируются через shared
  `pg_advisory_xact_lock(4201, 1)`. Atomic purge+record-run в
  одной tx под lock'ом. Commit-order guarantee заменяет prev
  "narrows race-window". §5.3/§8.2 обновлены на новую семантику.
- **1.14 (2026-04-22)** — PR-L2.2: честные формулировки race-
  properties. Формулировки "race-free" заменены на "narrows
  race-window" в retention_hold.go комментарии, enterprise_wire.go
  и runbook §5.3/§8.2. Явно указан residual race-window (под
  READ COMMITTED hold ПОСЛЕ начала DELETE не защитит rows в
  этом statement'е). True race-free design (SERIALIZABLE +
  advisory lock) — roadmap PR-L3. Также scheduler заменил
  concrete `(*audit.Repository)` type assertion на structural
  interface assertion (`holdAwarePurger`), decorator-friendly;
  при fallback пишется admin-event, не silent log.
- **1.13 (2026-04-22)** — PR-L2.1: race-fix. Scheduler переключён
  с snapshot→delete two-step на single-SQL
  `PurgeOlderThanRespectingHolds` (NOT EXISTS ... FROM legal_holds).
  Устранено snapshot-delete race-window (hold applied между
  snapshot'ом и delete'ом теперь защищает rows). Runbook §5.3
  уточнён: автоматическое retention-aware scope only для
  enterprise scheduler; core-only CLI остаётся `[manual]`.
- **1.12 (2026-04-22)** — PR-L2: retention-aware audit purge.
  Enterprise scheduler `runAuditPurgeScheduler` теперь вызывает
  `PurgeOlderThanExcept(cutoff, chunk, heldUserIDs)`, где
  `heldUserIDs` = `legalhold.Service.ActiveUserIDs()` snapshot.
  Fail-closed: hold-lookup error → skip tick. §8.2 retention-aware
  gap закрыт.
- **1.11 (2026-04-22)** — PR-G2.1: defence-in-depth для duplicate
  role entries. `evaluateRoleRules` собирает rules со ВСЕХ
  matching role entries (не early-return на первом), что делает
  Evaluate robust к direct-SQL / legacy import duplicates. Fix
  stale package comment в governance/types.go.
- **1.10 (2026-04-22)** — PR-G2: role-based governance.
  `Mode=role_based` + `Policy.RoleRules` в Policy model. Proxy
  передаёт `claims.Role` в `Evaluate`; unknown role → 403 +
  `code=unknown_role`. Deny-by-default для не-перечисленных ролей.
  Migration 014 (добавляет `role_rules_json` column).
- **1.9 (2026-04-22)** — PR-L1.3: scope fix для PR-L1.2 startup
  validation. `LEGAL_HOLD_TOKEN_SECRET` теперь enforce'ится ТОЛЬКО
  в enterprise build (через `//go:build enterprise` split в
  `validate_enterprise.go` / `validate_core.go`). Pure Apache core
  deploy не требует этого env var — поддерживает L-1 build
  contract. Также fix: `tokenizer.warnedUnkeyed` → `sync.Once`
  (устранение data race в dev fallback path при concurrent
  requests).
- **1.8 (2026-04-22)** — PR-L1.2: keyed HMAC для case_ref token'а
  (`LEGAL_HOLD_TOKEN_SECRET`, prod required, >=32 chars). Ранее
  plain SHA-256 — теперь HMAC-SHA256 truncated 64 bit, не
  brute-force'абелен оффлайн для guessable case-ID форматов.
  Runbook §8.2: статус `[gap]`/`[planned]` переведён в
  `[implemented]` — убрано противоречие с §5.
- **1.7 (2026-04-22)** — PR-L1.1: privacy+error-split hardening для
  legal hold. `case_ref` больше не дублируется в `admin_event_logs`
  / SIEM — только `case_ref_hash` (SHA-256 truncated к 16 hex).
  Handler error paths разведены на validation (400)/not-configured
  (503)/internal (500) generic responses; machine-readable
  `error_code` в admin-event вместо raw error string.
- **1.6 (2026-04-22)** — PR-L1: §5 переведён в `[implemented]`.
  Legal hold получил полноценную application-layer automation
  (`legal_holds` table, admin endpoints, pre-tx enforcement в
  ErasureService, admin-audit trail). Manual backup-freeze и
  audit-retention pause остаются operator'ской ответственностью.
- **1.5 (2026-04-22)** — PR-S1.1: §8.4 дополнен prod-guards для SIEM:
  empty endpoint / non-https / `InsecureSkipVerify` без override —
  rejected в `ValidateStartupConfig`. Защита от misconfigured
  mirror в prod.
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

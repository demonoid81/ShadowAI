# bd-ShadowAI-ldb: PR-D.1 — Admin-events retention + dashboard privacy

**Дата:** 2026-04-19
**Статус:** реализовано.

## Контекст

PR-D добавил отдельную таблицу `admin_event_logs`, но оставил два
privacy-gap'а:

1. **Нет retention для admin_event_logs.** Admin events копились
   без TTL, что потенциально нарушает data-minimization principles
   и compliance SLA (обычно 1-2 года, не forever).
2. **`/dashboard/top-users` светит raw email** как primary identifier.
   Screenshots админки → direct PII leak в Slack/Jira/email threads.

PR-D.1 закрывает оба.

## Контракт

### `ADMIN_AUDIT_RETENTION_DAYS`
Новая env-переменная (default 0 = no-purge). Независимая от
`AUDIT_RETENTION_DAYS`, потому что admin events имеют другие SLA.

### Общий purge через `audit_purge_runs.target`
Migration 011 добавляет колонку `target VARCHAR(64) NOT NULL DEFAULT 'audit_logs'`.
Существующие rows (PR-A) получают default 'audit_logs'. Новые
purge-runs для admin_event_logs записываются с `target='admin_event_logs'`.

Альтернатива — отдельная таблица `admin_audit_purge_runs` —
отклонена: две почти идентичные таблицы раздувают schema и усложняют
status endpoint (два JOIN'а вместо одного WHERE).

### CLI `cmd/audit-purge --target`
```
audit-purge --retention-days 30                           # default audit_logs
audit-purge --retention-days 365 --target admin_event_logs
audit-purge --retention-days 30 --target audit_logs --dry-run
```

Whitelist: `audit_logs | admin_event_logs`. Мусор → exit 1.

### Второй scheduler в `main.go`
При `AUDIT_PURGE_INTERVAL > 0 && ADMIN_AUDIT_RETENTION_DAYS > 0`
запускается отдельная goroutine для admin_event_logs (с собственным
cutoff, но тем же chunk_size). Оба scheduler'а отменяются через
общий `connectivityCtx`.

### `/audit/status` с `admin_events` блоком
```json
{
  "payload_mode": "redacted",
  "retention_days": 30,
  "last_purged_at": "2026-04-19T12:00:00Z",
  "rows_purged_total": 1234,
  "scheduler_enabled": true,
  "admin_events": {
    "retention_days": 365,
    "last_purged_at": "2026-04-19T11:00:00Z",
    "rows_purged_total": 42,
    "scheduler_enabled": true
  }
}
```

Два независимых блока. `scheduler_enabled` для каждого отражает
реальное состояние (interval > 0 И retention > 0).

### Dashboard email masking

Было:
```json
{"user_id":"uuid","email":"john.doe@example.com","requests":42,"cost":0.03}
```
Стало:
```json
{"user_id":"uuid","email_masked":"jo***@example.com","requests":42,"cost":0.03}
```

- Local part ≥ 3 символов → первые 2 + `***`.
- Local part ≤ 2 символов → `*` (не выдаём короткие локали).
- Нет `@` → `***` (маркер "не email").
- Пусто → `""`.

Domain сохранён: обычно соответствует tenant/company и не является PII.
Operator для полного email идёт через `GET /api/users/{id}` —
явный шаг, аудируется в admin_event_logs.

**Breaking change для frontend:** поле переименовано `email → email_masked`.
Frontend admin UI должен адаптироваться.

## Реализация

### Backend
- **migration 011_add_target_to_audit_purge_runs.sql** + index по
  `(target, started_at DESC)`.
- **domain.PurgeRun.Target** — opt field.
- **config.AdminAuditRetentionDays** — env `ADMIN_AUDIT_RETENTION_DAYS`.
- **audit.Repository** — все retention-методы получили `target`
  параметр; обратная совместимость через `""` → `audit_logs`.
- **adminaudit.Repository.PurgeOlderThan** — новый метод для
  admin_event_logs (chunked DELETE).
- **adminaudit.PurgeTarget** const = "admin_event_logs".
- **audit.Repo interface** обновлён (signature break: все call-site'ы
  передают target). Stubs в tests обновлены.
- **cmd/audit-purge** — flag `--target`, whitelist + routing в
  соответствующий PurgeOlderThan. `recordPurgeAdminEvent` получает
  target в metadata.
- **main.go** — второй goroutine для admin-events purge при
  retention + interval > 0.
- **audit.Handler.NewHandler** — принимает `adminEventsRetentionDays`
  + `adminEventsSchedulerEnabled`. Status endpoint расширен
  `admin_events` блоком.
- **dashboard.Handler** — `maskEmail(email)` применяется в
  `GetTopUsers` к raw email из БД; поле `EmailMasked`; `Email`
  полностью убрано.

### Тесты
- **dashboard/mask_test.go** (новый):
  - 8 cases `TestMaskEmail` (none, короткий/средний/длинный local,
    long domain, no-@, @-leading).
  - `TestMaskEmail_NeverReturnsRaw` — property-style guard против
    регресса (для любого local ≥3 символов full-substring не
    появляется в result'е).
- **existing tests** обновлены под новые NewHandler signatures
  (+2 params для admin-events).

## Операционный runbook (обновление)

### Включить retention для admin events
```
ADMIN_AUDIT_RETENTION_DAYS=365    # 1 год (compliance default)
AUDIT_PURGE_INTERVAL=24h
```
Проверка: `GET /audit/status` → `admin_events.scheduler_enabled=true`.

### Manual admin-events purge
```bash
./audit-purge --retention-days 365 --target admin_event_logs
```

### Audit full email после masking
Когда operator видит `jo***@example.com` в топе и хочет reach out:
```bash
curl -H "Authorization: Bearer $ADMIN" \
  "$URL/api/users/$USER_ID"      # получит full user object
# Операция уже аудируется в admin_event_logs как read/user (через
# существующий auth.Handler.GetUser — future PR может добавить wire).
```

## Размышления

- **Почему общий target column, не две таблицы.** DRY для purge-
  tracking (status endpoint один JOIN, не два). Cost — VARCHAR(64)
  на каждый row; на объёмах purge_runs (≤ 10K/year) несущественно.
- **Почему default=0 (no-purge) вместо 365.** Backward-compat:
  существующие deploy не должны внезапно начать удалять admin-
  events. Явный opt-in оператором.
- **Почему `email_masked` а не `email` с masked value.** Явное имя
  поля сигналит потребителю (admin UI / CSV export), что это не
  direct PII. Пре-PR-D.1 CSV export с колонкой `email` мог
  попасть в compliance-ловушку.
- **Почему local part 2 символа, не hash.** Hash (даже stable) не
  позволяет operator'у узнать "мой ли это john" за секунду;
  первые 2 символа + domain дают instant recognition без leak
  всего local part'а.
- **`SchedulerEnabled` честный bool.** Если задан только retention
  (без interval), scheduler не запускается — PR-D.1 сохраняет эту
  семантику отдельно для audit и admin.

## Definition of Done

- [x] Migration 011 добавляет `target` колонку.
- [x] `ADMIN_AUDIT_RETENTION_DAYS` в config + env.
- [x] `audit_purge_runs` для admin events работает через общий
      CLI и scheduler.
- [x] `/audit/status` отдаёт отдельный `admin_events` блок.
- [x] `/dashboard/top-users` возвращает `email_masked`, не raw email.
- [x] 2 новых dashboard теста (exact cases + property-guard).
- [x] Все existing handler-signature updates не ломают regression.
- [x] `go test ./...` зелёный.

## Out of scope (roadmap)

- **PR-E: Backup / Legal Hold / Privacy runbook** — pure-docs +
  retention matrix (retention-SLA, backup-policy, DSAR-vs-backups,
  incident/breach steps).
- **PR-F: Tenant isolation** — только если multi-tenant.
- **Frontend email-masked migration** — admin UI должна читать
  `email_masked` вместо `email`. Отдельный frontend PR.
- **Admin UI для admin-events filtering** — есть API endpoint
  (PR-D), но нет UI. Отдельный PR.

## Acceptance

- [x] Admin events живут по отдельному retention policy.
- [x] Dashboard не светит raw email как primary identifier.
- [x] Purge по admin audit предсказуем (те же API-endpoints
      и success/fail paths что для audit_logs).
- [x] Operator может объяснить:
      - сколько хранится audit / admin-events (retention_days,
        scheduler_enabled в `/audit/status`);
      - что purge'ится (rows_purged_total с историей);
      - что остаётся (scrubbed columns задокументированы в PR-B
        docs).

# Обсуждение следующей задачи — L7 legal hold SLA / DPO alerting

## Тема / вопрос

Определить следующую задачу roadmap после L6 scoped legal hold enforcement.

## Контекст

CASS был проверен перед анализом, но недоступен как актуальный источник: `cass health` вернул `index stale`. Поэтому источником стали локальные документы и фактический код.

Локальный поиск показал:

- `docs/production-hardening.md` всё ещё фиксирует `query_scope` legal hold как не реализованный.
- `docs/compliance/soc2-iso-control-mapping.md` фиксирует остатки: нет автоматического SLA escalation для hold durations и нет автоматического DPO notification при DSAR.
- `docs/privacy-ops-runbook.md` фиксирует SLA/escalation на неподтверждённые pending как roadmap.
- Кодовая база уже содержит legal hold lifecycle, pending/release_pending states, SLA visibility endpoint и admin/SIEM event foundation.
- BYOK2 документирован в RFC как реализация после customer/KMS provider decision, поэтому без такого решения это speculative implementation.

## Размышления

Рассмотрены варианты:

- **L6.1 / L7 query_scope selector language** — закрывает оставшийся scope gap, но требует отдельной threat model: selector DSL, допустимые поля, SQL-safe compilation, explainability для аудитора и interaction с tenant/org boundaries.
- **L7 legal hold SLA / DPO alerting** — использует уже существующую lifecycle-модель и pending-SLA visibility, добавляет автоматические сигналы для legal/compliance operations.
- **BYOK2 implementation** — важный enterprise ask, но RFC прямо требует предварительного выбора KMS/provider и решений по DEK TTL/searchable encryption.
- **Formal policy docs / BCP / vendor assessment** — полезно для audit-readiness, но это documentary/control work, не engineering blocker.

Принято рекомендованное направление: **PR-L7 — legal hold SLA escalation + DPO notification signals**.

Альтернатива `query_scope` отклонена как immediate next task: без selector RFC есть риск создать непроверяемый DSL с security/tenant-isolation ошибками.

Альтернатива BYOK2 отклонена до появления customer/KMS decision, потому что текущий RFC явно оставляет открытые вопросы.

## Рекомендованная задача

### КОНТЕКСТ

Legal hold lifecycle уже реализован: apply/release проходят через 4-eyes, `active` и `release_pending` блокируют DSAR/purge, `date_range` enforcement закрыт в L6. Но operational layer пока в основном pull-based: operator может посмотреть pending/SLA, но система сама не создаёт обязательные compliance-сигналы.

### ТЕКУЩЕЕ СОСТОЯНИЕ

- Есть `legal_holds` со статусами `pending`, `active`, `release_pending`, `released`.
- Есть admin events и SIEM mirror.
- Есть endpoint visibility для pending older than threshold.
- Есть Prometheus/Helm alerting infrastructure.
- Нет автоматического SLA breach signal для pending/release_pending holds.
- Нет автоматического DPO/legal notification signal при DSAR submission.

### ЗАДАЧА

**PR-L7: Legal hold SLA escalation and DPO notification signals**

Добавить автоматические machine-readable сигналы для legal/compliance operations:

- pending hold старше SLA threshold;
- release_pending hold старше SLA threshold;
- DSAR submission, требующий DPO/legal review;
- DSAR blocked by hold, требующий legal follow-up.

### ТРЕБОВАНИЯ

- Не добавлять email/SMS provider в v1.
- Основной v1 channel: admin_event_logs + SIEM + Prometheus metrics/alerts.
- Не раскрывать PII в alert labels.
- Tenant isolation: tenant admin видит только сигналы своего org; global_admin видит все.
- Break-glass события не должны обходить audit/SIEM.
- SLA thresholds должны быть configurable через env/Helm.
- Alerts должны быть actionable: в metadata нужен `hold_id`, `org_id`, `status`, `age_hours`, `threshold_hours`, но без raw `case_ref`/`reason`.
- Повторные сигналы должны быть rate-limited или idempotent per hold/status/window, чтобы не заспамить SIEM.
- Existing endpoint `/pending-sla` не ломать; можно переиспользовать repository/service query.

### КРИТЕРИИ ГОТОВНОСТИ

- Добавлены config fields:
  - `LEGAL_HOLD_PENDING_SLA_HOURS`
  - `LEGAL_HOLD_RELEASE_PENDING_SLA_HOURS`
  - `LEGAL_HOLD_SLA_SCAN_INTERVAL`
  - optional `DSAR_DPO_SIGNAL_ENABLED`
- Scheduler периодически ищет pending/release_pending holds старше threshold.
- Для каждого breach создаётся admin event с machine-readable `error_code`/`event_code`.
- SIEM получает те же события через existing recorder path.
- Prometheus metrics добавлены:
  - `shadowai_legal_hold_sla_breaches_total{status}`
  - `shadowai_legal_hold_sla_oldest_age_hours{status}`
  - `shadowai_dsar_dpo_signal_total{result}`
- Helm PrometheusRule добавляет alerts:
  - `LegalHoldPendingSLABreached`
  - `LegalHoldReleasePendingSLABreached`
  - `DSARBlockedByLegalHold`
- DSAR submission и DSAR blocked-by-hold пишут DPO/legal signal event без raw request body.
- Tests покрывают:
  - pending breach detected;
  - release_pending breach detected;
  - non-breach ignored;
  - duplicate scan does not emit duplicate event in same window;
  - tenant isolation in list/report path;
  - DSAR blocked-by-hold emits signal;
  - config validation rejects negative/zero invalid intervals.
- Проверки:
  - `go test -tags enterprise ./internal/legalhold ./internal/auth ./internal/adminaudit -count=1`
  - `go test -tags enterprise ./... -count=1`
  - `go test -tags 'enterprise integration' ./integration/... -count=1`
  - `make helm-validate`

### ДОПОЛНИТЕЛЬНО

- Не строить arbitrary notification transport в этом PR; webhook/email лучше делать отдельным `L7.1`.
- Не добавлять raw `case_ref`, `reason`, email или user body в metric labels.
- Не делать query_scope в этом PR.
- Не менять hold lifecycle states.
- Если нужен persistent dedupe, предпочтительнее отдельная append-only table `legal_hold_sla_events` или reuse admin_event lookup по `(hold_id,status,threshold,day_bucket)`; решение выбрать перед реализацией.

## Открытые вопросы

- Нужна ли persistent dedupe table или достаточно daily bucket через `admin_event_logs` lookup?
- Должен ли DSAR submission всегда сигналить DPO, или только когда blocked by hold?
- Threshold defaults: 24h для `pending`, 24h/48h для `release_pending`?

## Возможные следующие шаги

1. Перед implementation через ast-index найти `PendingOlderThan`, `HasActiveHold`, DSAR erase flow, admin recorder и scheduler wiring.
2. Создать bd-задачу `PR-L7: legal hold SLA escalation and DPO signals`.
3. Начать с red tests для SLA scan и DSAR blocked-by-hold signal.

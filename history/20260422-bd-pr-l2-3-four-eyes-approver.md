# PR-L2.3 — 4-eyes approver workflow для legal hold

**Дата:** 2026-04-22
**Ветка:** `pr-l2-3-four-eyes-approver`
**Предшественник:** PR-L4 (PG integration harness), PR-L3 (advisory-lock coordination)
**Тип:** enterprise feature (compliance)

---

## Контекст

PR-L1 реализовал базовый legal hold (`apply` → immediately
`is_active=true`), PR-L2/L2.1/L2.2/L3 — retention-aware purge с
race closure через `pg_advisory_xact_lock`. Однако один admin
мог применить hold самовольно: apply + delete чужого audit'а в
пределах одной админской сессии — в принципе возможно, если
scheduler не успел покрыть окно между "dsar request blocked" и
"audit purged".

Compliance-требование для enterprise deploy'ев (SOC2 / GDPR
operational controls): separation-of-duties. Privileged action,
последствие которого — материальная задержка erasure или
защита audit'а от retention, — должна проходить через
независимого second admin.

## Цель

Ввести 4-eyes approver workflow: create создаёт **pending**,
второй admin делает explicit approve. До approve hold НЕ effective
(не блокирует DSAR, не защищает от purge). Self-approval
блокируется на handler + repo level с отдельным SIEM-alerting
event code.

## Scope

### In
- `legal_holds.status` column (`pending | active | released`).
- `approved_at`, `approved_by` columns.
- Расширенный partial-unique index: "один blocking (pending OR
  active) per user" вместо старого "один active per user".
- Новые endpoints:
  - `POST /api/legal-holds/{id}/approve` — pending → active с
    4-eyes проверкой.
  - `POST /api/legal-holds/{id}/reject` — pending → released
    (cancel). Rejector может совпадать с creator.
- Renamed admin event action `apply_hold` → `apply_hold_requested`;
  added `apply_hold_approved`, `apply_hold_rejected`.
- SQL retention-aware purge переключён с `is_active=true` на
  `status='active'` (pending НЕ защищает audit).
- `HasActiveHold` / `ActiveUserIDs` переключены на
  `status='active'`.
- Runbook §5.2/§5.3/§5.5 обновлены под новый workflow.
- ENTERPRISE.md — migration 015 в списке.

### Out (roadmap v2+)
- 4-eyes для release (на сейчас release делает один admin).
- SLA / escalation engine на неподтверждённые pending.
- Bulk approvals.
- UI для approver queue.
- Hold-scope шире user-level (query-window, date-range).

## Рассмотренные варианты

### A. Отдельная таблица `pending_legal_holds`
Плюсы: чистое разделение request и applied; миграция не ломает
существующие queries.
Минусы: дублирование схемы и индексов; две таблицы для одной
сущности усложняют operator-mental-model и SIEM correlation (два
события по разным resource типам для одного hold'а); GET /legal-holds
должен UNION'ить. Отклонено — single-table подход с status column
проще и прозрачнее.

### B. `status` column + сохранение `is_active` как derivative (ВЫБРАН)
Плюсы: backward compat (старые запросы по `is_active` продолжают
работать), single source of truth — `status`, минимальная migration
risk. Hot-path (`HasActiveHold`, retention purge) целевается на
status='active' через specialized partial index.
Минусы: дублирование состояния (risk рассинхронизации). Митигация:
все writes делают update обоих полей атомарно в одной UPDATE.

### C. `status` column, удаление `is_active`
Плюсы: single source of truth без дублирования.
Минусы: breaking change для operator DB-queries / dashboards,
требует большего migration footprint. Отложено на v2.

## Принятые решения

- **Self-approval блокируется на repo-слое** с FOR UPDATE row lock,
  чтобы нельзя было обойти approve через concurrent modification.
  Отдельный ErrSelfApproval → 403 на handler, с
  `metadata.error_code=self_approval` для SIEM alerting.
- **Reject допускает self** — это cancellation собственного
  request'а, не approval. Compliance-logic: creator может "забрать
  заявку", это не создаёт risk'а.
- **Pending не защищает audit**. Выбор в пользу стрикта: если
  hold не прошёл review — он compliance-невидим. Альтернатива
  (pending защищает, pending не блокирует DSAR) — путаница для
  operator'а и для purge-scheduler'а.
- **Partial-unique index** расширен на `pending OR active`. Второй
  pending поверх существующего — 409 Conflict. Это предотвращает
  spam'ом pending-requests от creator'а в обход 4-eyes.
- **is_active сохраняется** как derivative status='active' для
  backward compat с SQL-queries в dashboards/ops tooling; все
  write-path'ы пишут оба значения в одной UPDATE.

## План реализации (выполнено)

1. Migration `015_legal_hold_status_four_eyes.sql`:
   status/approved_at/by, расширенный partial index, check-constraint.
2. `legalhold/types.go`: Status type + константы, поля Hold.
3. `legalhold/repository.go`: ErrNotPending/ErrSelfApproval,
   Create→pending, Approve FOR UPDATE+4-eyes, Reject, обновлённые
   Release/List/HasActiveHold/ActiveUserIDs/checkExistsInactive.
4. `legalhold/service.go`: Repository interface расширен; Service
   wrapper Approve/Reject; helpers IsNotPending/IsSelfApproval.
5. `audit/retention_hold.go`: SQL purge переключён на
   `status='active'`.
6. `legalhold/handler.go`: action rename + Approve/Reject HTTP
   handlers с разведёнными error paths; holdResponse расширен
   status/approved_at/by.
7. `cmd/shadowai/enterprise_wire.go`: новые routes /approve и
   /reject.
8. Тесты: service_test.go переписан под pending semantics;
   handler_test.go обновлён + добавлены Approve/Reject сценарии
   (happy / self-approval 403 / not pending 409 / NotFound /
   NonAdmin); regression guard TestPendingHold_DoesNotBlockDSAR.
9. Runbook §5 — новый workflow, SIEM breaking changes зафиксированы.
10. ENTERPRISE.md — migration 015.
11. Changelog 1.17.

## Definition of Done

- [x] Migration 015 применима отдельно и idempotent (IF NOT EXISTS).
- [x] Create возвращает pending; pending не блокирует DSAR.
- [x] Approve работает только с другим admin'ом; self-approval
      → 403 + admin event с error_code=self_approval.
- [x] Reject работает на pending; на active → 409.
- [x] Release работает только на active; на pending → 409.
- [x] Retention-aware purge экранирует только status='active'.
- [x] `go build ./...` и `go build -tags enterprise ./...` зелёные.
- [x] `go test ./... -count=1` — зелёный (core).
- [x] `go test -tags enterprise ./... -count=1` — зелёный
      (включая integration legalhold_purge_test на PG).
- [x] Runbook §5 обновлён; Changelog 1.17.
- [x] ENTERPRISE.md — migration 015.
- [ ] Commit + merge в master.

## Риски / зависимости

- **Breaking change для SIEM consumers**. Старые rules на
  `action=apply_hold` exact-match перестанут matchить новый
  `apply_hold_requested`. Changelog 1.17 и runbook §5.2 явно
  документируют. Migration path: operators обновляют SIEM rule-sets
  одновременно с deploy.
- **Data migration**: existing `is_active=true` rows получают
  `status='active'` по DEFAULT в migration 015. `is_active=false`
  → `status='released'` явным UPDATE. Новых rows created после
  migration попадают в pending автоматически.
- **Operational risk**: если operator только один admin, они не
  смогут approve собственный hold. На production это должно
  покрываться тем, что prod deploy имеет >= 2 admins (compliance
  требование уровня organization'а). В runbook §5.3 это сделано
  явным шагом "Step 2 — другой admin".

## Roadmap (v2+)

1. 4-eyes для release (сейчас release делает один admin).
2. SLA / escalation: pending старше N минут → автоматический
   alert legal-on-call.
3. Bulk approvals: один call approve'ит несколько pending по
   case_ref filter.
4. UI для approver queue (`pending_legal_holds` dashboard).
5. Auto-release по external webhook (legal CMS сигнал).
6. Hold-scope шире: per-query (audit row selector), per-date-range.
7. Remove `is_active` column (cleanup после migration 015 settle'ится).

## Self-check

- Режим: IMPLEMENTATION.
- A/B/C clarification: A (запрос был конкретным и детальным).
- TDD: частично — тесты обновлялись итеративно после core
  изменений; новые Approve/Reject сценарии написаны до финального
  прогона и зелёные с первого запуска.
- Размышления оформлены в переформулированном виде ниже без
  первого лица и без логов исследования:

> Рассмотрены варианты отдельной таблицы pending_holds и single-table
> со status column. Принято решение в пользу status column с
> сохранением is_active для backward compat. Альтернатива
> "удалить is_active сразу" отклонена из-за operator-risk breaking
> change.

- Коммит: выполняется в заключительном шаге.

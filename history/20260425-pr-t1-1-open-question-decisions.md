# PR-T1.1 — Open Question Decisions (OQ-2…OQ-5)

**Date:** 2026-04-25  
**Status:** Closed — всех 4 OQ закрыты, PR-T2 разблокирован  
**RFC:** docs/rfcs/2026-04-pr-t1-tenant-isolation.md §D6

---

## Контекст

PR-T1 RFC был clean по ревью, но оставлял 4 открытых вопроса
(OQ-2…OQ-5), которые формально блокировали начало реализации T2.
Цель T1.1 — зафиксировать решения без изменения кода/миграций.

---

## D6.1 — SCIM org source (OQ-2)

**Решение:** один SCIM Bearer token = один org_id. X-Org-ID header отклонён.

Рассмотрены варианты:
- Header (`X-Org-ID`): spoofable, требует runtime validation, сложен в audit.
- Bearer token scope: неизменяем после выдачи, org binding server-side.

Принято решение: token-scoped подход. Альтернатива отклонена по
причине audit и security risk.

T2 consequence: новая таблица `scim_tokens` с `org_id UUID NOT NULL`.
SCIM middleware резолвит org из token record, не из request.

---

## D6.2 — Budget model (OQ-3)

**Решение:** per-user budgets tenant-safe через users JOIN. Org aggregate cap → T2.1/G4.

Рассмотрены варианты:
- Per-user + org aggregate cap: слишком широкий scope для isolation PR;
  org cap добавляет product semantics (block on cap hit? UI?).
- Per-user only, tenant-safe через JOIN: механический, безопасный для T2.

Принято решение: per-user, tenant-safe. Альтернатива отклонена
как out-of-scope для isolation задачи.

T2 consequence: budget handlers проверяют `targetUser.org_id == claims.org_id`
через JOIN. Колонка `org_id` в `budgets` не добавляется — избыточна.

---

## D6.3 — Global CLI semantics (OQ-4)

**Решение:** dangerous global operations требуют explicit флаги.

| Tool | Поведение по умолчанию | Global флаг |
|------|------------------------|-------------|
| `audit-export-evidence` | Требует `--org-id` | `--global` (только global_admin) |
| `audit-purge` | Требует `--org-id` | `--all-orgs` (только global_admin) |
| `audit-verify` | Глобально (read-only) | `--org-id` для tenant-scoped отчёта |

Рассмотрены варианты:
- Auto-detect из JWT: неявное поведение, одинаковый binary → разный output
  в зависимости от роли. Опасно в скриптах и runbook'ах.
- Explicit флаги: scope виден на call site.

Принято решение: explicit opt-in. Verify допускает global default потому что
read-only верификация цепи не имеет side effects.

---

## D6.4 — internal_db_sources scope (OQ-5)

**Решение:** org-scoped by default. Shared/global sources → отдельный RFC.

Рассмотрены варианты:
- Global shared sources: DSN содержит credentials и schema visibility;
  shared source между org'ами = cross-tenant schema leak risk.
- Org-scoped: каждый org имеет свои sources; sharing через отдельный PR
  с `scope=org|global` колонкой и authorization rules.

Принято решение: org-scoped по умолчанию. Альтернатива отклонена
как preemptive complexity без подтверждённого use case.

T2 consequence: `org_id UUID` добавляется в `internal_db_sources` в Phase 1.
Все `/api/internal-dbs/*` reads фильтруются по `claims.org_id`.

---

## Следующий шаг: PR-T2.1 Schema Seed

Первый implementation PR. Содержит только миграции, zero code changes:

- `organizations` таблица + default org row
- `org_id` columns на всех tenant-scoped таблицах
- `canonical_version` на chained таблицах
- `source_org_id` / `target_org_id` в `admin_event_logs`
- `scope` в `audit_purge_runs`
- `scim_tokens` таблица

После прохождения smoke (`go test -tags 'enterprise smoke' ./smoke/...`) →
переход к Phase 2 (auth claims + SCIM middleware).

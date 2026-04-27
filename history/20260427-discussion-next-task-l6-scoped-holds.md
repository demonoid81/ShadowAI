# Обсуждение следующей задачи — L6 scoped legal holds

## Тема / вопрос

Определить следующую задачу roadmap и расписать её в рабочем формате.

## Контекст

Локальный поиск по актуальным документам показал два крупных остатка:

- `docs/production-hardening.md` фиксирует, что legal hold пока whole-user only, а enforcement date-range scope оставлен на L6.
- `docs/production-hardening.md` также фиксирует BYOK как не реализованный, но с оговоркой на customer requirement.
- `docs/rfcs/2026-04-pr-byok1-kms-byok-design.md` указывает, что provider-specific KMS integration — BYOK2 scope.
- `docs/privacy-ops-runbook.md` отдельно помечает hold-scope шире user-level как roadmap gap.

CASS был проверен, но недоступен как свежий источник: `cass health` вернул stale index. Поэтому источником истины для выбора стали локальные документы и кодовая база.

## Размышления

Рассмотрены варианты:

- **BYOK2** — важный security/compliance трек, но локальный RFC явно связывает provider integration с customer/KMS decision. Без выбранного KMS-провайдера реализация рискует стать speculative.
- **G4.3 budget alerts** — полезная операционная задача, но не выглядит блокером перед regulated go-live.
- **L6 scoped legal holds** — уже зафиксирован как Known Limit Before GA и как privacy-ops gap; недавно усиленный tenant/legal-hold контекст делает задачу естественным продолжением.

Принято рекомендованное направление: **L6 — enforcement date-range/query-scope legal holds**.

Альтернатива BYOK2 отклонена как следующая immediate task до появления customer/KMS decision. Альтернатива G4.3 отклонена как менее критичная для legal/compliance correctness.

## Рекомендованная задача

### КОНТЕКСТ

Legal hold сейчас работает как whole-user блокировка: если hold активен или находится в release flow, DSAR/purge блокируются по пользователю целиком. В документах уже указано, что date-range/query-scope hold является roadmap gap.

### ТЕКУЩЕЕ СОСТОЯНИЕ

- Есть таблица `legal_holds` и append-only `legal_hold_events`.
- Есть 4-eyes lifecycle: `pending → active → release_pending → released/active`.
- DSAR и retention-aware purge умеют учитывать active/release_pending holds.
- Tenant scope и `org_id` для hold/event были усилены.
- Scope model частично задуман, но enforcement за пределами whole-user не реализован.

### ЗАДАЧА

**PR-L6: scoped legal hold enforcement**

Реализовать enforcement для legal hold scope шире whole-user:

- `whole_user` — текущее поведение;
- `date_range` — hold блокирует только данные target user в заданном временном диапазоне;
- `query_scope` / selector scope — минимальный безопасный v1 как structured metadata selector, если уже есть schema support; иначе оставить как validated future field без enforcement.

Рекомендуемый v1: реализовать **date_range enforcement end-to-end**, а query-scope оставить fail-closed/unsupported до отдельного PR, если текущая schema не готова.

### ТРЕБОВАНИЯ

- Не ломать существующие whole-user holds.
- Existing holds без scope должны вести себя как `whole_user`.
- DSAR whole-user erasure должен блокироваться любым active/release_pending hold на пользователя, включая date-range hold, потому что DSAR удаляет всё.
- Retention purge должен исключать только строки, попадающие в active/release_pending date-range hold.
- Audit purge evidence должен честно отражать, что часть строк была исключена legal hold scope.
- Tenant isolation сохраняется: tenant admin не может создать/просмотреть/освободить hold для чужого org.
- Legal hold events должны фиксировать scope changes/creation metadata без PII в свободном тексте сверх уже принятой модели.
- API должен валидировать диапазон: `start <= end`, timezone UTC, пустые границы запрещены для `date_range`.
- Query-scope, если не реализуется, должен возвращать явный `400 unsupported_scope_type`, а не silently fallback to whole-user.

### КРИТЕРИИ ГОТОВНОСТИ

- `CreateHold` принимает scope fields и сохраняет их.
- Legacy create без scope создаёт `whole_user`.
- `HasActiveHold(userID)` продолжает блокировать DSAR для whole-user и date-range holds.
- Retention purge исключает только audit rows внутри date-range hold.
- Rows вне date-range purge удаляет как обычно.
- Release/approve/reject flow не ломается для scoped holds.
- `legal_hold_events` создаются для create/approve/reject/request_release/approve_release/reject_release с корректным `org_id`.
- Regression tests покрывают:
  - whole-user legacy hold;
  - date-range hold блокирует purge внутри диапазона;
  - date-range hold не блокирует purge вне диапазона;
  - DSAR блокируется date-range hold;
  - invalid range → 400;
  - unsupported query_scope → 400;
  - tenant cross-org create/list/release denied.
- Проверки:
  - `go test -tags enterprise ./internal/legalhold ./internal/audit ./internal/auth -count=1`
  - `go test -tags enterprise ./... -count=1`
  - `go test -tags 'enterprise integration' ./integration/... -count=1`
  - `go test -tags 'enterprise smoke' ./smoke/... -count=1`

### ДОПОЛНИТЕЛЬНО

- Не использовать metadata_json как единственный источник enforcement, если scope fields уже есть в schema или требуют first-class columns.
- Не превращать date-range hold в whole-user fallback при ошибке парсинга.
- Не удалять строки вне диапазона, если query construction ambiguous.
- Не делать UI в этом PR.
- Не делать SLA escalation в этом PR.
- Не делать automatic DPO notifications в этом PR.

## Открытые вопросы

- Есть ли уже first-class columns для `scope_type`, `scope_start`, `scope_end`, или нужна migration?
- Должен ли `date_range` применяться к `audit_logs.created_at`, `admin_event_logs.created_at`, или только к DSAR/audit purge surface?
- Нужна ли отдельная evidence/report строка для количества строк, исключённых scoped hold.

## Возможные следующие шаги

1. Перед implementation через ast-index найти `Hold`, `HasActiveHold`, `ActiveUserIDs`, purge call-sites и существующие scope fields.
2. Создать bd-задачу `L6 scoped legal hold enforcement`.
3. Начать с red tests для date-range purge behavior.

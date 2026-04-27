# bd ShadowAI-7n1 — PR-L6 scoped legal hold enforcement

## Контекст

Задача продолжает legal-hold трек после L5. Локальные документы фиксировали gap: legal hold scope шире whole-user был roadmap-остатком. Обсуждение задачи сохранено в `history/20260427-discussion-next-task-l6-scoped-holds.md`.

CASS перед реализацией был проверен:

- `cass health` — сервис доступен.
- `cass search "L6 scoped legal holds date range enforcement" --robot --limit 5` — прямых совпадений нет.
- `cass search "Hold-scope wider user-level date-range query-window" --robot --limit 5` — прямых совпадений нет.
- `cass search "legal hold scope date range purge DSAR" --robot --limit 5` — найден предыдущий контекст L5/privacy-ops, где date-range/query-scope указаны как v2+ gap.

Фактический код показал, что `scope_type`, `scope_date_from`, `scope_date_to` уже присутствуют в enterprise schema, но create/list/repository и purge enforcement их не использовали.

## Цель

Реализовать L6 v1: scoped legal hold enforcement для `date_range`, сохранив legacy `whole_user` поведение и fail-closed поведение для неподдержанного `query_scope`.

## Входит в объём

- API create legal hold принимает `scope_type`, `scope_date_from`, `scope_date_to`.
- Legacy create без scope создаёт `whole_user`.
- `date_range` требует обе границы, UTC-normalization и `from <= to`.
- Retention-aware purge защищает только audit rows target user внутри active/release_pending date-range.
- Whole-user holds продолжают защищать все audit rows target user.
- DSAR-level `HasActiveHold` остаётся user-wide: любой active/release_pending hold блокирует whole-user erasure.
- `query_scope` и неизвестные scope values возвращают validation error, а не silently fallback.
- DB constraint фиксирует допустимые комбинации scope fields.
- Документация обновляется: date-range больше не listed gap; query-scope остаётся future work.

## Не входит в объём

- Query selector language.
- UI.
- SLA escalation.
- DPO notifications.
- Отдельная статистика количества rows, исключённых scoped hold.
- Scoped enforcement для не-audit таблиц за пределами текущего retention purge surface.

## План реализации

1. Добавить доменные scope constants и service-level validation для `whole_user`, `date_range`, `query_scope`.
2. Расширить legal hold handler request/response и error mapping.
3. Расширить repository INSERT/SELECT/scan paths, чтобы scope fields сохранялись и возвращались.
4. Обновить retention-aware purge SQL: whole-user OR date-range intersection against `audit_logs.created_at`; `release_pending` продолжает защищать.
5. Добавить enterprise migration с CHECK constraint и индексом для active/release_pending date-range lookup.
6. Добавить red/green тесты для service, handler и PG integration purge behavior.
7. Обновить docs/history, прогнать enterprise/core/integration/smoke проверки, закрыть bd и сделать commit.

## Размышления

Рассмотрены варианты:

- Реализовать сразу `date_range` и полноценный `query_scope`.
- Реализовать только schema/API без enforcement.
- Реализовать `date_range` end-to-end, а `query_scope` явно отклонять до отдельного selector-language PR.

Принято решение: L6 v1 реализует `date_range` end-to-end. Это закрывает зафиксированный compliance gap без введения непроверенного query language.

Альтернатива с полноценным `query_scope` отклонена: selector language требует отдельной threat model, ограничения expressiveness и доказуемого SQL-safe исполнения.

Альтернатива с fallback `query_scope` → `whole_user` отклонена: такой fallback скрывает ошибку оператора и может создать чрезмерную блокировку, которую сложно объяснить аудитору.

## Критерии готовности

- `CreateScopedHoldInOrg` валидирует и сохраняет scope.
- Create API возвращает scope fields.
- Legacy holds остаются `whole_user`.
- Invalid date range возвращает validation error.
- `query_scope` возвращает 400/validation error.
- Retention purge удаляет rows вне date-range и сохраняет rows внутри date-range.
- `release_pending` hold защищает audit rows до approve release.
- Released hold больше не защищает rows.
- DB constraint не допускает некорректные persisted scope combinations.
- Документация больше не утверждает, что date-range не реализован.

## Проверка

- `go test -tags enterprise ./internal/legalhold -run 'TestL6|TestCreate_DateRange|TestCreate_QueryScope' -count=1`
- `go test -tags 'enterprise integration' ./integration/... -run 'TestCoord_DateRangeHold_ProtectsOnlyRowsInsideRange|TestCoord_ReleasePendingStillProtects|TestCoord_ApprovedThenReleased_NoLongerProtects' -count=1`
- `go test -tags enterprise ./internal/legalhold -count=1`
- `go test -tags enterprise ./internal/legalhold ./internal/audit ./internal/auth -count=1`
- `go test -tags enterprise ./... -count=1`
- `go test -tags 'enterprise integration' ./integration/... -count=1`
- `go test -tags 'enterprise smoke' ./smoke/... -count=1`
- `go test ./... -count=1`
- `make helm-validate`
- `git diff --check`

## Риски / зависимости

- `query_scope` остаётся intentionally unsupported; операторы должны использовать `whole_user` или `date_range`.
- `HasActiveHold` остаётся user-wide, потому что DSAR удаляет пользователя целиком и не может безопасно частично игнорировать date-range hold.
- `ActiveUserIDs` остаётся summary-oriented для metadata; фактическая purge-защита теперь живёт в SQL predicate.
- Старые holds без scope совместимы через default `whole_user`.

## Roadmap

### v1

- `whole_user` + `date_range` enforcement для audit retention purge.
- `query_scope` fail-closed.

### v2+

- Selector/query-scope model с ограниченным DSL.
- Evidence/reporting количества rows, исключённых scoped holds.
- SLA escalation и DPO notifications.

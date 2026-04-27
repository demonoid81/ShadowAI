# Обсуждение следующей задачи — L8.1c query_scope purge enforcement

## Тема / вопрос

Определить следующую задачу после `PR-L8.1b: query_scope create + WORM canonical v2`.

## Контекст

Фактические источники:

- `history/20260427-bd-ShadowAI-4ue-l8-1b-query-scope-create-worm.md`
  фиксирует roadmap v2+: query-scoped purge protection, selector manifest,
  optional BYOK encryption.
- `docs/rfcs/2026-04-pr-l8-legal-hold-query-scope-rfc.md` Phase 4 требует:
  обновить `PurgeOlderThanRespectingHoldsAndRecordRun`, компилировать
  active/release-pending `query_scope` holds в `NOT EXISTS` protection,
  invalid stored selector должен abort purge tick и писать
  `legal_hold_query_scope_compile_failed`.
- `docs/production-hardening.md` всё ещё содержит stale status:
  `query_scope` not implemented / returns validation error. После L8.1b это
  уже частично неверно: create реализован, enforcement ещё нет.

CASS-поиск `L8.1c query_scope purge enforcement legal hold roadmap` не нашёл
релевантных записей; источником истины остаются локальные документы и код.

## Размышления

Рассмотрены варианты:

1. Делать `L8.1c` purge enforcement.
2. Делать evidence bundle selector manifest.
3. Сначала делать только docs cleanup по stale production-hardening/privacy
   runbook.

Принято решение рекомендовать `L8.1c` как следующий шаг: после L8.1b продукт
уже позволяет создавать `query_scope` hold, но retention purge ещё не умеет
уважать selector. Это главный remaining semantic gap.

Альтернатива evidence bundle manifest отклонена как следующий шаг: bundle
важен для аудитора, но без purge enforcement созданный `query_scope` hold всё
ещё не даёт selective retention protection.

Альтернатива standalone docs cleanup отклонена как отдельный PR: stale docs
лучше обновить внутри L8.1c, потому что статус снова изменится.

## Варианты решений

### Вариант A — PR-L8.1c query_scope purge enforcement

Плюсы:

- закрывает главный runtime gap после L8.1b;
- приводит поведение retention purge в соответствие с RFC Phase 4;
- invalid stored selector становится fail-closed, а не silent data loss.

Минусы:

- security-sensitive SQL path;
- нужны regression/integration tests вокруг purge, active/release_pending и
  invalid stored selector.

### Вариант B — PR-L8.1d selector manifest for evidence bundle

Плюсы:

- улучшает auditor portability;
- логично после WORM canonical v2.

Минусы:

- не закрывает runtime enforcement;
- может экспортировать selector semantics до того, как enforcement доказан.

### Вариант C — docs-only cleanup

Плюсы:

- быстро убирает stale wording.

Минусы:

- не решает технический gap;
- потребует повторного обновления после L8.1c.

## Рекомендованное направление

Следующая задача: **PR-L8.1c — legal hold `query_scope` purge enforcement**.

## Открытые вопросы

- Нужен ли отдельный admin event на successful query-scope protected purge tick,
  или достаточно existing purge run evidence + failure event для invalid stored selector.
- Должен ли invalid stored selector блокировать только текущий purge target или весь
  purge tick для таблицы. Рекомендация: блокировать весь tick, потому что это
  fail-closed compliance path.

## Возможные следующие шаги

1. По команде пользователя создать bd-задачу `PR-L8.1c: query_scope purge enforcement`.
2. Реализовать через TDD: purge rows inside selector protected, outside selector
   deleted, invalid stored selector aborts.
3. Обновить stale docs: `docs/production-hardening.md`,
   `docs/privacy-ops-runbook.md`.

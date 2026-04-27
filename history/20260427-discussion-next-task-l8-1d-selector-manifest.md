# Обсуждение следующей задачи — L8.1d selector manifest для evidence bundle

## Тема / вопрос

Определить следующую задачу после `PR-L8.1c: query_scope purge enforcement`.

## Контекст

Фактические источники:

- `history/20260427-bd-ShadowAI-ctp-l8-1c-query-scope-purge.md` фиксирует
  roadmap v2+: evidence bundle selector manifest.
- `docs/rfcs/2026-04-pr-l8-legal-hold-query-scope-rfc.md` D11 требует
  selector manifest lines в evidence bundle: `hold_id`, `scope_type`,
  `selector_hash`, `selector_json`.
- `docs/production-hardening.md` после L8.1c фиксирует оставшийся gap:
  portable evidence bundles still do not include selector manifest.

CASS-поиск `L8.1d selector manifest evidence bundle query_scope` не нашёл
релевантных session-записей; источником истины стали локальные docs/history.

## Размышления

Рассмотрены варианты:

1. Делать `L8.1d` selector manifest в evidence bundle.
2. Перейти к BYOK selector encryption.
3. Перейти к distributed governance cache invalidation.

Принято решение рекомендовать `L8.1d`: runtime path для `query_scope`
закрыт (create/WORM/purge), но auditor-facing portability ещё неполная.
Без selector manifest bundle содержит hash, но не объясняет, какие строки
selector должен был защищать.

Альтернатива BYOK отклонена как следующий шаг: payload encryption важен для
customer-managed privacy, но не закрывает текущий auditability gap.

Альтернатива governance invalidation отклонена как unrelated track: это
операционный performance/consistency gap, а L8 ещё имеет незакрытый evidence
контракт.

## Варианты

### Вариант A — PR-L8.1d selector manifest

Плюсы:

- закрывает Acceptance Criteria PR-L8: evidence bundle contains selector
  manifest or hash-only record with disclosure;
- делает query-scope holds explainable для auditor без live DB;
- естественно продолжает L8.1b/L8.1c.

Минусы:

- нужно аккуратно разграничить tenant/global bundle, чтобы не раскрыть чужие
  selectors;
- selector JSON может раскрывать расследовательскую стратегию.

### Вариант B — BYOK selector encryption

Плюсы:

- снижает exposure selector details для global admin/storage.

Минусы:

- требует KMS/BYOK implementation, а это отдельный большой track;
- не заменяет manifest, только меняет формат payload.

### Вариант C — Governance cache distributed invalidation

Плюсы:

- закрывает known GA operational limit.

Минусы:

- не связан с L8 evidence chain;
- не завершает query_scope story.

## Рекомендация

Следующая задача: **PR-L8.1d — evidence bundle selector manifest for
query_scope legal holds**.

## Открытые вопросы

- Нужен ли hash-only export флаг сразу в v1 или достаточно documented
  default с selector JSON. Рекомендация: default JSON manifest + optional
  `--selector-manifest=hash-only|full` только если уже есть CLI config pattern.
- Должен ли tenant bundle включать только selectors своего org. Рекомендация:
  да, tenant bundle не должен раскрывать cross-tenant selectors.

## Возможные следующие шаги

1. По команде пользователя создать bd-задачу `PR-L8.1d: evidence bundle
   selector manifest`.
2. Найти export path через ast-index: `audit-export-evidence`,
   `evidencebundle`, tenant/global bundle modes.
3. Реализовать manifest + offline verification hash check.

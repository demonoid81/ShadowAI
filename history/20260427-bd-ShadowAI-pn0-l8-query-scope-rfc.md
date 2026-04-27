# bd ShadowAI-pn0 — PR-L8 query_scope legal hold RFC

## Контекст

После L6 legal hold умеет `whole_user` и `date_range`. После L7
добавлены SLA/DPO machine-readable signals. Локальные документы
фиксируют остаточный gap: `query_scope` / per-query / per-conversation
hold не реализован.

CASS перед реализацией был проверен, но недоступен как актуальный
источник: `cass health` вернул `index stale`. Поэтому источником истины
стали локальные docs и фактический код.

## Цель

Создать RFC, который фиксирует безопасную модель `query_scope` до
implementation PR.

## Входит в объём

- RFC в `docs/rfcs/`.
- Threat model.
- JSON DSL decision.
- Field/operator allowlist.
- Normalization/canonical hash.
- SQL-safe compilation contract.
- Preview/explain contract.
- WORM/evidence implications.
- L8.1 implementation breakdown.

## Не входит в объём

- Parser/compiler code.
- DB migrations.
- API implementation.
- UI.
- External legal CMS integration.
- BYOK/KMS.

## План реализации

1. Проверить CASS и bd.
2. Через ast-index найти `Hold`, scope constants, purge function,
   WORM canonical и evidence inventory.
3. Прочитать targeted ranges в `legalhold`, `audit`, `chain`.
4. Написать RFC с decision log и rejected alternatives.
5. Зафиксировать минимум 5 examples.
6. Проверить `rg`/`git diff --check`, закрыть bd и сделать commit.

## Размышления

Рассмотрены варианты:

- Реализовать full query parser сразу.
- Сначала написать RFC.
- Использовать text DSL / SQL-like WHERE.
- Использовать JSON DSL.

Принято решение: PR-L8 является design-only RFC, а реализация parser /
compiler уходит в L8.1.

Альтернатива с immediate implementation отклонена: selector language
затрагивает tenant boundary, purge correctness и WORM evidence; без
зафиксированного дизайна высок риск security bug.

Альтернатива с SQL-like text DSL отклонена: слишком высокий injection и
reviewability risk.

JSON DSL выбран как v1, потому что его проще валидировать, нормализовать
и хэшировать.

## Критерии готовности

- RFC файл создан.
- RFC явно design-only.
- Зафиксированы decisions по DSL, fields, operators, canonicalization,
  preview/explain, WORM/evidence.
- Есть threat model и rejected alternatives.
- Есть L8.1 implementation breakdown.
- Есть examples file.
- `git diff --check` проходит.

## Проверка

- `rg -n 'query_scope|L8|selector' docs/rfcs/2026-04-pr-l8-legal-hold-query-scope-rfc.md history/20260427-bd-ShadowAI-pn0-l8-query-scope-rfc.md`
- `git diff --check`

## Риски / зависимости

- Existing dirty worktree содержит несвязанные изменения; их нельзя
  stage/revert.
- CASS index stale.
- `conversation_id` не является first-class `audit_logs` column, поэтому
  per-conversation hold должен быть deferred до L8.2 или отдельной schema
  работы.

## Roadmap

### v1

- RFC/design-only.

### v2 / L8.1

- Migrations.
- `legalholdselector` package.
- Preview endpoint.
- Purge integration.
- WORM canonical v2 for legal hold events.

### v3 / L8.2+

- `conversation_id` audit column.
- UI selector builder.
- Legal CMS webhook integration.

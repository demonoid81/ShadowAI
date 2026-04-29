# Обсуждение: оставшиеся frontend-задачи

## Тема / вопрос

Какие задачи остались после закрытия UX7.

## Контекст

Перед ответом проверены источники:

- `cass health` — CASS не инициализирован, архив сессий недоступен.
- `bd list --status open --json`.
- `bd ready --json`.

Фактический открытый backlog содержит один epic и три готовые к работе задачи.

## Размышления

Рассмотрены варианты: перечислить только ready-задачи или включить epic. Принято решение показать и epic, и дочерние задачи, потому что epic отражает границы frontend-доработки, а дочерние задачи являются реальной очередью исполнения.

Альтернатива опираться на историю чата отклонена: по контракту проекта прошлый контекст не является источником истины.

## Оставшиеся задачи

1. `ShadowAI-ux8` — Governance Policy v2 UI.
2. `ShadowAI-ux9` — Compliance report workspace.
3. `ShadowAI-ux10` — Operations live health and dashboard accuracy.
4. `ShadowAI-9zi` — epic `Full solution: Enterprise frontend console completion`, остаётся открытым до закрытия UX8-UX10.

## Рекомендованное направление

Следующей брать `ShadowAI-ux8`, потому что это priority 1 и закрывает управляемость enterprise governance policy v2 из UI. После этого логичный порядок: UX9, затем UX10.

## Открытые вопросы

- Нужно ли расширять backend admin events API server-side org/status фильтрами после UX7.
- Нужен ли backend inventory endpoint для evidence/report bundles после UX9.

## Возможные следующие шаги

1. Реализовать UX8.
2. После UX8 закрыть UX9.
3. После UX9 закрыть UX10 и затем закрыть epic `ShadowAI-9zi`.

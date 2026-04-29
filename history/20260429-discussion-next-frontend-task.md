# Следующая frontend-задача

## Тема / вопрос

Какая следующая задача после закрытия `ShadowAI-ux9`.

## Контекст

Локальный источник `.beads/issues.jsonl` показывает epic `ShadowAI-9zi` — `Full solution: Enterprise frontend console completion`. В его плане последним открытым child item указан `UX10: Operations live health + dashboard accuracy`.

Задача `ShadowAI-ux10` имеет статус `open` и описывает разрыв между live usage stats на Dashboard и статическими readiness/posture cards, а также отсутствие live health секции на Operations page.

## Размышления

Рассмотрены варианты продолжить frontend epic или переключиться на новый backend/security gap. Принято решение рекомендовать завершить текущий frontend epic, потому что `ShadowAI-ux10` является последней открытой задачей в обнаруженном frontend roadmap.

Альтернатива с добавлением новых backend capabilities отклонена для этого шага: scope `ShadowAI-ux10` явно требует использовать только существующие safe endpoints/signals и не рисовать фиктивные зелёные статусы.

## Варианты

1. `ShadowAI-ux10` — Operations live health and dashboard accuracy.
   Плюсы: закрывает последний frontend epic gap; снижает риск misleading UI; использует существующие endpoints.
   Минусы: часть production signals останется unknown, если нет backend API.

2. Создать новую backend task для CronJob/Prometheus summary API.
   Плюсы: даст richer live ops UI.
   Минусы: это v2+ зависимость, не нужна для закрытия UX10 v1.

## Рекомендованное направление

Брать `ShadowAI-ux10`.

## Открытые вопросы

- Достаточно ли для v1 existing endpoints: `/api/health`, `/api/ready`, `/proxy/firewall/status`, `/api/audit/status`.
- Нужно ли добавить отдельный backend gap после UX10 для CronJob/Prometheus summary endpoint.

## Возможные следующие шаги

1. По команде пользователя перейти в IMPLEMENTATION.
2. Открыть `ShadowAI-ux10` через `bd`, перевести в `in_progress`.
3. Проверить реальные API-контракты страниц Dashboard/Operations.
4. Реализовать honest live/static split и unknown states.

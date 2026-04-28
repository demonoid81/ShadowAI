# bd ShadowAI-rhl.2 — F7.8 cross-chunk PII sanitize

## Контекст

Задача `ShadowAI-rhl.2` закрывает gap incremental streaming sanitize: DLP/PII inspection работает по sliding window, но emit path может переписать только текущий delta frame. Если sensitive value разрезан между несколькими chunks, первая часть уже могла быть отправлена клиенту до того, как window увидел полный паттерн.

CASS был проверен перед реализацией: `cass health` сообщил stale index, а non-interactive search по cross-chunk PII не нашёл результатов. Поэтому источником истины выступили фактический код, bd-задача и локальные docs.

## Цель

Исключить silent leakage для PII, найденной только на границе chunks, без изменения bytes-identity allow path и без попытки ретроактивно переписать уже отправленные bytes.

## Scope

In:
- Тесты на PII, разрезанную между chunks.
- Safe fallback для unsafe sanitize verdict.
- Regression guard: уже sanitized finding в предыдущем chunk не должен блокировать следующий clean chunk.
- Обновление production docs.

Out:
- Полноценный delayed-emission/window rewrite.
- Изменение provider adapter framing.
- Снятие `STREAMING_ALLOW_INCREMENTAL_IN_PROD`.

## План реализации

1. Добавить red-тесты для split email в `incrementalEngine`.
2. Добавить end-to-end test для OpenAI-compatible SSE: второй chunk не должен попасть клиенту, audit должен получить `stream_blocked_midflight`.
3. Добавить byte-offset tracking в engine.
4. Классифицировать findings относительно текущего delta: current-only, prior-only, cross-boundary.
5. Для cross-boundary sanitize verdict возвращать block с marker `cross-chunk`.
6. Обновить docs и examples.
7. Прогнать proxy/core/enterprise regression.

## Размышления

Рассмотрены варианты:
- Полноценный window rewrite с задержкой эмита на один или несколько chunks.
- Safe fallback через mid-stream block при unsafe sanitize verdict.
- Оставить текущую sanitize-current-delta семантику и полагаться на audit review.

Принято решение: использовать safe fallback. Причина: incremental mode уже мог отправить первую половину sensitive value, поэтому корректная ретроактивная redaction невозможна без изменения latency/transport semantics. Блокировка completing chunk — минимальное безопасное поведение для v1.

Альтернатива с delayed-emission отклонена для F7.8: она меняет real-time contract, требует provider-specific buffering policy и отдельного proof window.

## Roadmap

v1:
- Cross-chunk sanitize verdict fail-closes в mid-stream block.
- Same-delta sanitize остаётся in-place redaction.
- Prior-only finding в sliding window не блокирует следующий clean delta.

v2+:
- Рассмотреть delayed-emission ring buffer для ограниченной window-aware redaction без mid-stream block.
- Добавить отдельный metric/label для cross-chunk sanitize block reason, если операторам потребуется отличать его от остальных mid-stream block.

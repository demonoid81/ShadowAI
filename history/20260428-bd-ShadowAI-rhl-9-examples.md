# bd ShadowAI-rhl.9 — примеры Gemini text+usage

## Happy path 1 — text + usageMetadata

Frame содержит `parts[].text="email user@example.com"` и `usageMetadata`.
Ожидаемо decoder возвращает `EventDeltaText`, а `Event.Usage` заполнен.

## Happy path 2 — sanitize text+usage

Тот же frame проходит через `EmitSanitized`: output содержит redacted marker,
исходный email отсутствует, `usageMetadata` остаётся в JSON.

## Edge case 1 — usage-only final frame

Frame с `usageMetadata`, `finishReason` и пустым text остаётся `EventUsageUpdate`
или terminal usage path как раньше. Существующий usage test не ломается.

## Edge case 2 — text-only frame

Обычный Gemini text-only frame остаётся `EventDeltaText`.

## Failure case — malformed text+usage JSON

Malformed JSON не должен превращаться в inspected delta; decoder отдаёт
`EventUnknownChunk`, а sanitize path по malformed delta возвращает error.

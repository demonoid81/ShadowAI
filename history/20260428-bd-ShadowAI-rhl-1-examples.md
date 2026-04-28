# bd ShadowAI-rhl.1 — примеры F7.7

## Happy path 1 — Anthropic content_block_delta

Входной frame:

```text
event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"email user@example.com"}}
```

Ожидаемый результат: `delta.text` заменён на sanitized value, `event:`
сохранён, исходный email отсутствует.

## Happy path 2 — Gemini SSE candidates parts

Входной frame содержит `candidates[].content.parts[].text` с email. Ожидаемый
результат: первый текстовый part содержит sanitized value, остальные text parts
очищены, `modelVersion` и structure сохранены.

## Happy path 3 — Ollama chat NDJSON

Входной line:

```json
{"model":"llama3","message":{"role":"assistant","content":"email user@example.com"},"done":false}
```

Ожидаемый результат: `message.content` заменён, line остаётся NDJSON с `\n`.

## Edge case 1 — Ollama generate shape

Входной line использует `/api/generate` форму с полем `response`. Ожидаемый
результат: `response` заменён, `message` не создаётся искусственно.

## Edge case 2 — control/empty delta events

Anthropic `content_block_start` и другие empty delta events не должны
мутироваться даже если `EmitSanitized` вызван напрямую. Identity сохраняется.

## Failure case — malformed delta JSON

Если `EventDeltaText` содержит malformed provider JSON, `EmitSanitized`
возвращает error. Silent identity запрещён: иначе sanitize verdict может
превратиться в незаметную утечку.

# bd ShadowAI-rhl.2 — примеры F7.8

## Happy path 1 — same-delta email

Input chunks:
- `contact `
- `user@example.com`

Ожидаемое поведение:
- Второй chunk содержит полный email внутри текущего delta.
- Engine возвращает `Sanitize=true`.
- Emitter переписывает текущий provider frame.
- Audit: `policy_action=sanitized`, `outcome=stream_completed`.

## Happy path 2 — clean stream after previous sanitize

Input chunks:
- `contact user@example.com`
- ` thanks`

Ожидаемое поведение:
- Первый chunk sanitizes.
- Второй chunk не блокируется, хотя raw email ещё находится в sliding window.
- Stream-level state остаётся `Sanitized=true`.

## Edge case 1 — split email across chunks

Input chunks:
- `contact user@`
- `example.com`

Ожидаемое поведение:
- Первый chunk проходит, потому что полного PII pattern ещё нет.
- На втором chunk sliding window видит полный email.
- Finding пересекает границу уже emitted bytes и текущего delta.
- Engine возвращает `Block=true`, `InspectorName=dlp`, reason содержит `cross-chunk`.
- Completing chunk не отправляется клиенту.

## Edge case 2 — prior-only finding in window

Input chunks:
- `email user@example.com`
- ` no more sensitive data`

Ожидаемое поведение:
- Finding полностью находится до начала текущего delta.
- Повторный DLP sanitize verdict от sliding window не мутирует clean delta.
- Engine продолжает stream без block.

## Failure case — unsafe sanitize silently emits completing chunk

Старое поведение:
- `contact user@` отправлялся клиенту.
- На `example.com` DLP находил email только в window.
- Sanitize применялся к текущему delta, но `pii.Scan("example.com")` ничего не находил.
- `example.com` уходил клиенту без redaction, завершая leaked email.

Новое поведение:
- Второй chunk не эмитится.
- Клиент получает terminal error frame.
- Audit фиксирует `stream_blocked_midflight`.

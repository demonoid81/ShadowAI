# bd ShadowAI-rhl.1 — F7.7 full incremental sanitize for non-OpenAI providers

## Контекст

Остаточный LLM firewall gap: в streaming adapters для Anthropic, Gemini и
Ollama `EmitSanitized` был identity-stub. Это означало, что incremental
engine мог получить sanitize verdict и записать `policy_action=sanitized`, но
байты, отправленные клиенту, для этих провайдеров не менялись.

Документы `docs/production-hardening.md` и
`docs/runbooks/streaming-production-proof.md` из-за этого запрещали включать
incremental production для Anthropic/Gemini/Ollama без дополнительного caveat.

## Цель

Закрыть provider-specific sanitize gap для поддерживаемых non-OpenAI streaming
wire formats:

- Anthropic SSE `content_block_delta.delta.text`
- Gemini SSE `candidates[].content.parts[].text`
- Ollama NDJSON `/api/chat message.content`
- Ollama NDJSON `/api/generate response`

## Scope In

- Red tests на sanitize rewrite для Anthropic/Gemini/Ollama.
- Error tests: malformed delta JSON должен вернуть error, а не silent identity.
- Identity tests для empty/control delta events.
- Реализация provider-specific JSON rewrite.
- Обновление docs, где был caveat про identity-stub.

## Scope Out

- Cross-chunk PII sanitize: отдельная задача `ShadowAI-rhl.2`.
- BYOK/KMS: отдельная задача `ShadowAI-rhl.4`.
- semantic_v2 promotion: отдельная задача `ShadowAI-rhl.5`.
- Удаление `STREAMING_ALLOW_INCREMENTAL_IN_PROD`: gate остаётся до production
  proof evidence.

## План реализации

1. Зафиксировать backlog gaps в bd под эпиком `ShadowAI-rhl`.
2. Изучить текущие adapters через ast-index и targeted reads.
3. Добавить tests в `backend/internal/proxy/streaming/roundtrip_test.go`.
4. Реализовать `EmitSanitized` в трёх adapter files.
5. Обновить production docs/runbook comments.
6. Прогнать targeted tests и enterprise regression.
7. Закрыть bd-задачу и сделать commit.

## Размышления

Рассмотрены варианты:

- **Silent identity on unsupported rewrite** — отклонено. Это сохраняет главный
  gap: audit говорит sanitized, но payload не меняется.
- **Transport error on malformed delta JSON** — принято. Для sanitize path
  лучше fail-visible, чем тихий leak.
- **Полностью byte-preserving rewrite** — отклонено как избыточное для sanitize
  path. Allow path остаётся byte-identity; sanitize path может re-encode JSON,
  если сохраняет семантику provider frame.
- **Window-aware cross-chunk rewrite в этой задаче** — отклонено. Это другой
  класс проблемы и заведён как `ShadowAI-rhl.2`.

## Roadmap

- v1: закрыть provider-specific `EmitSanitized` stubs.
- v2+: закрыть cross-chunk PII и production proof evidence.

## Проверка

- `go test ./internal/proxy/streaming -count=1`
- `go test ./internal/proxy -count=1`
- `go test -tags enterprise ./... -count=1`
- `git diff --check`

## Результат реализации

- Anthropic `EmitSanitized` переписывает `content_block_delta.delta.text`.
- Gemini `EmitSanitized` переписывает `candidates[].content.parts[].text`.
- Ollama `EmitSanitized` переписывает `message.content` или `response`.
- Empty/control delta events остаются identity.
- Malformed delta JSON возвращает error без partial write.
- Handler-level regression подтверждает, что incremental transport для
  Anthropic/Gemini/Ollama реально отдаёт redacted output и выставляет
  `Sanitized=true`.
- Production docs обновлены: прежний identity-stub caveat заменён на
  оставшийся F7.8 caveat про cross-chunk PII.

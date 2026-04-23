# PR-F7.1 — Streaming Transport Layer (normalized events + paired adapters)

**Дата:** 2026-04-23
**Ветка:** `pr-l2-3-four-eyes-approver` (продолжение серии; отдельный
branch не нужен, PR-F7.1 — чистый transport, не трогает security
семантику).
**RFC:** `docs/rfcs/2026-04-pr-f7-streaming-architecture.md`
(§8.2 normalized events, §8.6 re-encoding contract, §9 provider
coverage, §19 implementation split).

---

## Контекст

PR-F7-RFC зафиксировал архитектуру перехода от full-buffered
streaming к incremental. F7.1 — первый implementation PR: строит
**транспортный слой**, на который потом сядут F7.2 (inspection
engine) и F7.3 (audit & accounting redesign).

Ключевая дисциплина F7.1 — узкий scope:
- normalized event model;
- paired decoder + emitter для tier-1 providers;
- round-trip bytes-identity тесты;
- feature flag + metrics foundation;
- handler wiring, который НЕ меняет default поведение.

Никаких новых security decisions, inspector logic, sanitize
rewrite или legacy removal.

## Реализовано

### Новый пакет `backend/internal/proxy/streaming/`

Структура:

- `events.go` — Event type, Usage, ProviderError, 5 EventType констант.
- `decoder.go` — `Decoder` interface.
- `emitter.go` — `Emitter` interface + `flushIfPossible` helper.
- `sse_reader.go` — shared `readSSEFrames` c сохранением raw bytes
  (отличается от существующего `walkSSE` тем, что не теряет
  терминаторы — обязательное условие для identity preservation).
- `adapter_openai_compat.go` — OpenAI / OpenRouter / Groq / Mistral.
- `adapter_anthropic.go` — named SSE events (message_start /
  content_block_* / message_delta / message_stop / ping / error).
- `adapter_gemini.go` — data-only SSE с usageMetadata.
- `adapter_ollama.go` — NDJSON с `done=true` финальным frame'ом.
- `adapter.go` — factory `AdapterForProvider(name string) (Adapter, bool)`
  + `SupportedProviders()`.
- `fixtures_test.go` — 7 canonical fixtures (OpenAI normal, OpenAI
  with usage, Anthropic named, Gemini SSE, Ollama NDJSON, OpenRouter
  keepalive, malformed).
- `roundtrip_test.go` — ядро F7.1: `decode(X) → emit = X` для всех
  adapter'ов.
- `adapter_test.go` — factory coverage, EmitError per-provider shape,
  семантические проверки decoder'а (usage fields, provider error
  mapping).

Ключевые design decisions:

1. **Пакет self-contained** — НЕ импортирует `proxy`, чтобы не
   создавать cycle. Factory диспатчит по provider **name** (string),
   не по Provider interface. Явно фиксирует (не комментом, а кодом,
   как попросил ревью) маппинг `openai|groq|mistral|openrouter` →
   OpenAICompatAdapter.
2. **Usage type локальный** — свой `streaming.Usage`, не
   `proxy.StreamUsage`, чтобы accounting redesign в F7.3 мог
   безопасно менять сигнатуры.
3. **Emit rejects empty RawBytes** — F7.1 invariant: без RawBytes
   emit возвращает error. Sanitize active usage — F7.2; здесь явно
   запрещено, чтобы случайно не эмитить bytes которых не было.
4. **Ollama done=true — один Event, не два** — финальный frame
   превращается в `EventUsageUpdate` с `Meta["done"]="true"`;
   terminating semantics выражается через Meta и естественный EOF.
   Альтернатива "два events из одной line" нарушила бы round-trip
   identity.
5. **Unknown chunk — identity passthrough** — malformed JSON или
   неизвестный event name → EventUnknownChunk с RawBytes без попытки
   re-encode. Caller инкрементит `streaming_malformed_chunk_total`.

### Config: `STREAMING_MODE`

- `backend/internal/config/config.go`: новое поле `StreamingMode`,
  env var `STREAMING_MODE` с дефолтом `"buffered"`.
- `NormalizeStreamingMode(raw string) string` — fallback на
  `"buffered"` для неизвестных значений (dev-friendly).
- `ValidateStartupConfig` в prod требует строго
  `buffered|incremental|shadow`; неизвестное значение — error.
- `shadow` зарезервирован; в F7.1 ведёт себя как `buffered`.

### Metrics (foundation, не весь набор из RFC §14)

- `shadowai_streaming_mode_total{mode,provider}` — rollout visibility.
- `shadowai_streaming_malformed_chunk_total{provider}` — parser
  regression signal.
- `shadowai_streaming_emit_fail_total{provider}` — downstream writer
  errors (client disconnect).
- `shadowai_streaming_fallback_total{provider,reason}` — transition
  из incremental в buffered.

Остальные метрики RFC §14 (`midstream_block_total`,
`inspection_latency_seconds`, `memory_accumulated_bytes`,
`shadow_divergence_total`) — отложены в F7.2/F7.3, т.к. без
inspection pipeline'а бессмысленны.

### Handler wiring

- `backend/internal/proxy/handler.go`: добавлено поле
  `streamingMode` + `SetStreamingMode(mode string)` setter. Без
  изменения `NewHandler` сигнатуры (все callers компилируются без
  правок).
- `backend/internal/proxy/handler_streaming_incremental.go`:
  вынесены helper'ы:
  - `runIncrementalStreamTransport` — transport-only pipeline
    (decode upstream, real-time emit, параллельный tee в buffer
    для post-stream accounting).
  - `shouldUseIncrementalStream(providerName)` — guard: режим ==
    incremental И adapter найден; инкрементит
    `streaming_fallback_total{reason="unsupported_provider"}` если
    нет.
- `ProxyChat` и `UnifiedChat` обе streaming-ветви получили
  incremental branch **перед** `io.ReadAll(resp.Body)`, который
  активируется только при successful `shouldUseIncrementalStream`.
  Default (buffered) остаётся на текущем path без изменений.
- `main.go`: `proxyHandler.SetStreamingMode(config.NormalizeStreamingMode(cfg.StreamingMode))`.

### F7.1 explicit compromise

В incremental mode F7.1 **не** выполняет response-side firewall /
DLP / sanitize inspection — только transport passthrough + audit +
budget. Это осознанное Stage-1 tradeoff (RFC §13.2):
- default config остаётся `buffered` → исторические deploy'и не
  затронуты;
- operator opt-in через env var STREAMING_MODE=incremental;
- F7.2 введёт incremental inspection.

Любой operator, включивший incremental на prod до F7.2, получает
latency benefit за счёт потери response-side inspection. Видимо
через метрику `streaming_mode_total{mode="incremental"}`.

## Тесты

Core + enterprise + PG integration — все зелёные.

**streaming package:**
- `TestRoundTrip_BytesIdentity` (9 subtests, включая openai/groq/
  mistral/openrouter/anthropic/gemini/ollama/openrouter-keepalive/
  malformed). Все adapter'ы сохраняют byte-identity.
- `TestRoundTrip_EventTypeCoverage` — смешанный Anthropic stream
  эмитит delta_text + usage_update + message_stop + unknown_chunk.
- `TestRoundTrip_OpenAI_DoneSentinel` — `[DONE]` → message_stop.
- `TestRoundTrip_Ollama_DoneFrame` — done=true → usage_update с
  Meta.done=true.
- `TestRoundTrip_Gemini_UsageInFinalFrame` — usageMetadata → usage_update.
- `TestRoundTrip_Malformed_EmitsUnknownChunk` — json error → unknown.
- `TestAdapterForProvider_KnownNames` / `_Unknown` — factory
  coverage.
- `TestOpenAICompatEmitter_EmitError_Format` / Anthropic / Gemini /
  Ollama EmitError — terminal frame format per-provider.
- `TestEmitter_RejectsEmptyRawBytes` — F7.1 invariant.
- `TestOpenAICompat_UsageFrame_Semantics` — usage fields правильно
  заполнены.
- `TestAnthropic_ProviderError_Mapping` / `TestOllama_ErrorLine_Mapping`.

**proxy handler wiring:**
- `TestProxyChat_Streaming_BufferedMode_UnchangedByF7_1` (3 subtests:
  default empty, explicit buffered, unknown fallback). Гарантия
  acceptance criterion §4 RFC — STREAMING_MODE=buffered не меняет
  поведения.
- `TestProxyChat_Streaming_IncrementalMode_BytesIdentity` —
  acceptance §5: incremental проходит transport без corruption.
- `TestProxyChat_Streaming_IncrementalMode_UnsupportedProvider_FallsBack` —
  unknown provider name → fallback без corruption.

## Acceptance criteria ревью (из задания)

- [x] Есть normalized event model (events.go).
- [x] Paired decoder/emitter для tier-1 providers (openai-compat,
      anthropic, gemini, ollama).
- [x] `decode(X) → emit == X` покрыт round-trip tests на 7 canonical
      fixtures.
- [x] STREAMING_MODE=buffered не меняет текущее поведение
      (проверено subtest'ом).
- [x] STREAMING_MODE=incremental проходит transport path без
      corruption (проверено subtest'ом).
- [x] Malformed chunk observable через
      `streaming_malformed_chunk_total`.
- [x] Core + enterprise builds зелёные (+ PG integration).
- [x] Никаких новых security regressions — default config buffered,
      handler buffered branch нетронут, NewHandler сигнатура
      неизменна.

## Что специально НЕ сделано в F7.1

(per user's explicit scope)

- Audit schema не менялась — `audit_logs.policy_action` остаётся
  как был.
- Budget semantics не менялись — `parseStreamingUsage` по-прежнему
  вызывается на full accumulated bytes.
- Incremental inspectors не введены.
- Sanitize не решён полностью — capability surface есть (Emit
  работает только с RawBytes; re-encode path адаптеров зарезервирован).
- Buffered path не удалён.

## Следующий PR

**PR-F7.2** — incremental response inspection engine + inspector
flags + fail modes + CM+judge buffered_fallback wiring (RFC §12.6).

## Файлы

Новые:
- backend/internal/proxy/streaming/{events,decoder,emitter,sse_reader,adapter,adapter_openai_compat,adapter_anthropic,adapter_gemini,adapter_ollama}.go
- backend/internal/proxy/streaming/{roundtrip_test,fixtures_test,adapter_test}.go
- backend/internal/proxy/handler_streaming_incremental.go
- backend/internal/proxy/handler_streaming_incremental_test.go

Изменённые:
- backend/internal/config/config.go (StreamingMode, NormalizeStreamingMode, prod validation)
- backend/internal/metrics/metrics.go (4 новых counter'а + Record helpers)
- backend/internal/proxy/handler.go (streamingMode field, SetStreamingMode, incremental branches в ProxyChat + UnifiedChat)
- backend/cmd/shadowai/main.go (SetStreamingMode вызов)

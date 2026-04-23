# PR-F7.2 — Incremental Response Inspection Engine

**Дата:** 2026-04-23
**Ветка:** `pr-l2-3-four-eyes-approver`
**Предшественники:** PR-F7.1 (transport), PR-F7.1.1 (prod gate + audit honesty), PR-F7.1.2 (metric classification)
**RFC:** `docs/rfcs/2026-04-pr-f7-streaming-architecture.md`
(§8.3-8.4, §12.1, §12.6)

## Контекст

PR-F7.1 дал pure transport layer (decoder+emitter, identity
preservation) без response-side enforcement. В prod incremental
mode был безопасным только при explicit opt-in через
STREAMING_ALLOW_INCREMENTAL_IN_PROD.

PR-F7.2 возвращает response-side enforcement в incremental path:
sliding window inspection + mid-stream block + CM+judge
buffered_fallback.

## Scope (ужесточённый per команде пользователя)

### In
- Incremental allow / flag / block.
- Explicit buffered_fallback (CM+judge.Enabled, unsupported provider).
- Sliding inspection window.
- Capability matrix на wire-time.
- Mid-stream block через emitter.EmitError + upstream close через
  ctx cancel (стандартный тec через resp.Body.Close в caller).
- Audit outcomes: streaming_flagged, streaming_blocked_midflight,
  streaming_buffered_fallback.
- Metrics: streaming_midstream_block_total{provider,inspector}.

### Out (sanitize исключён per ужесточению)
- Sanitize rewrite mid-stream — в F7.2 ActionSanitize
  **downgrade'ится до flag** (stream продолжается без модификации).
- Budget redesign.
- Shadow mode compare engine.
- Provider parity beyond tier-1.
- Removal of buffered path.
- Full runbook docs.

## Реализация (два внутренних шага как советовал пользователь)

### Шаг 1: capability + engine + wiring

**`backend/internal/proxy/streaming_capability.go`** — новый файл.
- `StreamingCapability` enum (`CapabilityIncremental` / `CapabilityBufferedFallback`).
- `CapabilityDecision` pair (Capability, Reason).
- `DecideStreamingCapability(*firewall.Pipeline) CapabilityDecision` — единственная проверка: CM+judge.Enabled → fallback, иначе incremental.
- Reasons: `judge_inspector`, `unsupported_provider`, `unsupported_inspector` (последний в F7.2 не используется, зарезервирован).

**`backend/internal/proxy/streaming/window.go`** — sliding inspection window.
- `InspectionWindow` с двумя bounded буферами: sliding window
  (default 8 KiB) + accumulated (default 256 KiB).
- `Append(delta)` усекает с начала при overflow.
- Cross-chunk pattern test: pattern разбитый на 12 single-char
  chunk'ов ловится в window.

**`backend/internal/proxy/streaming_incremental_engine.go`** —
новый файл.
- `incrementalEngine` с firewall.Pipeline + dlp.Service + window.
- `EvaluateDelta(ctx, delta) incrementalVerdict` возвращает
  `{Block, Flag, InspectorName, Reason}`.
- F7.2 правила:
  - firewall.ActionBlock → Block verdict.
  - firewall.ActionFlag → accumulate flag state, продолжаем.
  - firewall.ActionSanitize → downgrade до flag (sanitize в
    scope'е F7.2 НЕ реализован).
  - dlp.Block → Block; dlp.Sanitize → flag.
- Fail-open на inspector errors (RFC §12.1 принцип).
- `Flagged()` / `FlaggedInspector()` — stream-level state для audit.

**`backend/internal/proxy/handler.go` + handler_streaming_incremental.go:**
- Handler получил два новых поля: `streamingCapability` (cached в
  SetStreamingMode) и `streamingFallbackLastReason` (ставится в
  `shouldUseIncrementalStream` при fallback'е, читается в buffered
  branch для audit marker'а).
- `shouldUseIncrementalStream` теперь проверяет capability →
  unsupported_provider или judge_inspector reason'ы уходят в
  streaming_fallback_total metric.
- `runIncrementalStreamTransport` принимает `*incrementalEngine`;
  возвращает `incrementalTransportResult` с `{Accumulated, Blocked,
  BlockInspector, BlockReason, Flagged, FlaggedInspector,
  TransportErr}`. Одна структура вместо 2-х return values.
- В decoder callback: EventDeltaText → EvaluateDelta → Block
  → EmitError (F7.1 transport primitive) + sentinel
  `errMidstreamBlock`.

### Шаг 2: mid-stream block + audit wiring

**5 audit markers констант** (4 из F7.1 + 3 F7.2):
- F7.1: `streaming_budget_exceeded_soft`, `streaming_transport_error`.
- F7.2: `streaming_flagged`, `streaming_blocked_midflight`,
  `streaming_buffered_fallback`.

**Audit classification priority** (consistent в обоих ProxyChat /
UnifiedChat incremental branches):
1. `res.Blocked` → StatusCode=403 + `streaming_blocked_midflight`.
2. `res.TransportErr != nil` → 502 + `streaming_transport_error`.
3. Budget over → 200 + `streaming_budget_exceeded_soft`.
4. `res.Flagged` → 200 + `streaming_flagged`.
5. Прочее → обычный policyAction.

**Buffered-branch fallback marker**: в буферном branche final
audit write override'ит `policyAction` на
`streaming_buffered_fallback`, если `streamingFallbackLastReason`
non-empty И `policyAction == dlp.DLPActionAllow` (не затирает
сильные сигналы block/sanitize).

**Новая метрика** `shadowai_streaming_midstream_block_total{provider,inspector}`.
Cardinality: ≤ 7 providers × ≤ 6 response-side inspectors = 42.

## Тесты

### Unit (streaming package)
- `TestInspectionWindow_*` (5 subtests): sliding bounds,
  accumulated cap, cross-chunk pattern.

### Unit (proxy package)
- `TestIncrementalEngine_*` (6 tests): nil inspectors,
  firewall.Block, firewall.Flag accumulation, Sanitize→flag
  downgrade, DLP.Block, cross-chunk pattern detection.
- `TestDecideStreamingCapability_*` (6 subtests): nil pipeline,
  empty pipeline, pattern-only inspectors, CM+judge.Enabled=true
  → fallback, CM без judge → incremental, CM+judge.Enabled=false
  → incremental.

### End-to-end handler (F7.2)
- `TestProxyChat_Incremental_MidstreamBlock_ClientGetsErrorFrame` —
  inspector block посреди stream'а: client получает 200 + partial
  stream + SSE `event: error` frame; audit StatusCode=403 +
  `streaming_blocked_midflight`.
- `TestProxyChat_Incremental_Flagged_AuditMarker` — flag inspector:
  stream проходит до конца byte-identical, audit помечен
  `streaming_flagged`.
- `TestProxyChat_Incremental_CMJudge_BufferedFallback` — CM с
  judge.Enabled → capability=fallback; stream идёт через buffered
  path, audit помечен `streaming_buffered_fallback`.
- `TestProxyChat_Incremental_CleanStream_AllowAudit` — regression
  guard: clean stream без inspector'ов не получает F7.2 markers.

### Существующие тесты
- Все F7.1 / F7.1.1 / F7.1.2 тесты продолжают проходить
  (новая сигнатура `runIncrementalStreamTransport` обновлена в
  `TestIncrementalTransport_MetricClassification` через
  `res.TransportErr` вместо второго return value).

## Acceptance criteria из задания

- [x] incremental mode больше не transport-only для supported
      inspectors (engine работает на PII/DLP/OutputValidation/CM-heuristic).
- [x] unsupported inspector combos → explicit buffered fallback
      (CM+judge.Enabled) + metric + audit marker.
- [x] CM+judge всегда fallback, не downgrade.
- [x] mid-stream block рвёт stream (EmitError + errMidstreamBlock
      sentinel + tee close) и пишет audit marker.
- [x] flagged streams проходят целиком и пишут audit marker.
- [x] core + enterprise test matrix зелёные.
- [x] prod gate STREAMING_ALLOW_INCREMENTAL_IN_PROD остаётся.

## Принятые решения

1. **Capability — wire-time cached decision**, а не per-request
   walk. `SetStreamingMode` вычисляет один раз. Это предполагает
   что firewall.Pipeline не мутирует после wire'а (что сейчас
   верно).
2. **Sanitize downgrade**, а не hard-reject. Пользователь сказал
   "не тащим sanitize"; engine downgrade'ит на flag, чтобы
   inspector'ы с Sanitize action'ами не ломали incremental path
   (они продолжают работать, просто теряют sanitize-capability).
3. **Audit marker через policyAction override**, не отдельное поле.
   domain.AuditLog не имеет metadata map; PolicyAction переиспользуется
   как channel. Precedence: block/sanitize/flag из firewall >
   streaming_buffered_fallback > allow.
4. **Fail-open на inspector error в F7.2** — consistent с buffered
   path, который тоже пропускает на error (`if fwErr == nil && ...`).
   RFC §12.1 разрешает оба fail mode; выбираем open на stage, где
   incremental ещё подтверждает стабильность.

## Следующий PR

**PR-F7.3** — streaming audit & accounting finalization:
- outcome classifier на основе RFC §11 (stream_completed /
  stream_upstream_error / stream_usage_parse_failed outcomes);
- accounting редизайн для mid-stream block (partial usage billing);
- возможно, удаление prod opt-in gate после достаточной
  стабилизации.

После F7.3 sanitize можно будет спокойно добавить в F7.4/F7.5
(RFC §13.3 Stage 2).

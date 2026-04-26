package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/shadowai/backend/internal/metrics"
	"github.com/shadowai/backend/internal/proxy/streaming"
)

// errTransportEmit — sentinel, которым wrapping'ом помечаются emit
// errors изнутри decoder callback'а. Позволяет отличить emit-phase
// error (writer broken / client disconnect) от decoder-phase error
// (upstream read fail / parser fatal) на стороне
// runIncrementalStreamTransport caller'а.
//
// Classification используется ТОЛЬКО для precise metrics (чтобы
// streaming_emit_fail_total не сливался с streaming_decoder_fatal_total).
// Сам сигнал "transport failed" одинаковый: audit пишется с
// streaming_transport_error маркером независимо от фазы.
var errTransportEmit = errors.New("streaming: downstream emit failed")

// PR-F7.3: PolicyAction'Streaming'*  константы удалены. Transport /
// accounting semantics перенесены в separate structured fields:
//   policy_action    — только policy/security verdict (allowed/
//                      blocked/flagged/sanitized).
//   outcome          — transport-level итог (см. streaming_audit.go
//                      Outcome*).
//   fallback_reason  — почему incremental не применён.
//   usage_source     — origin accounting data.
// Compound marker hack (streaming_buffered_fallback:<original>) из
// F7.2.1 удалён строго — dashboards должны быть обновлены синхронно
// с deploy.

// errMidstreamBlock — sentinel для выхода из decoder callback'а
// когда inspector сказал block. Обёрнут так, чтобы caller-side
// различал его от emit/decoder ошибок.
var errMidstreamBlock = errors.New("streaming: mid-stream block")

// incrementalTransportResult — возвращаемое значение
// runIncrementalStreamTransport v2. Объединяет accumulated bytes,
// состояние blocked/flagged/sanitized и transport error в одну
// структуру, чтобы caller мог принять решение об audit.
type incrementalTransportResult struct {
	Accumulated []byte
	// Blocked — inspector mid-stream вернул block (EmitError уже
	// вызван внутри транспорта).
	Blocked        bool
	BlockInspector string
	BlockReason    string
	// Flagged — incremental engine накопил flag (любой из delta был
	// flagged). Stream прошёл до EOF.
	Flagged          bool
	FlaggedInspector string
	// Sanitized — PR-F7.5: хотя бы один delta был sanitized.
	// Stream прошёл до EOF; emitted bytes содержат sanitized text.
	Sanitized          bool
	SanitizedInspector string
	// TransportErr — non-cancel error от decoder/emitter. nil при
	// успешном пропуске или при normal block. Обработка в caller
	// (audit StatusCode=502 + streaming_transport_error marker).
	TransportErr error
}

// runIncrementalStreamTransport — PR-F7.1 transport-only pipeline.
// Читает upstream через provider-specific decoder, немедленно эмитит
// RawBytes каждого event'а в w (real-time passthrough), и параллельно
// аккумулирует байты для post-stream accounting/audit.
//
// F7.1 scope (explicit):
//   - transport integrity (bytes-identity для allow path);
//   - parallel накопление RawBytes для parseStreamingUsage совместимости;
//   - real-time flush к клиенту.
//
// F7.1 сознательно НЕ делает:
//   - incremental response-side firewall/DLP inspection (это F7.2);
//   - sanitize (F7.2);
//   - mid-stream block (F7.2, через emitter.EmitError как transport
//     primitive, уже готовый в adapter'ах).
//
// Precondition: caller убедился, что STREAMING_MODE=incremental И
// AdapterForProvider(providerName) вернул (adapter, true). Если
// adapter отсутствует, caller обязан fallback'ить на buffered path
// и инкрементить metrics.RecordStreamingFallback.
//
// Behavior:
//   - headers + status записываются до начала emit'а (чтобы клиент
//     увидел SSE handshake сразу);
//   - каждый Event'овский RawBytes emit'ится через adapter.Emitter;
//   - все bytes накапливаются в accumulated buffer для parseStreamingUsage;
//   - decoder / emitter errors пишут metric и прерывают stream с
//     best-effort audit (caller ответственен за audit write).
//
// Returns:
//   - accumulated — все bytes upstream stream'а (byte-identical с
//     тем, что прочитан из resp.Body; нужны для parseStreamingUsage
//     и — в F7.2/F7.3 — для полной audit/inspection);
//   - err — если decoder или emitter фатально упали; nil при
//     нормальном завершении включая client disconnect (ctx.Err
//     возвращается тоже).
func (h *Handler) runIncrementalStreamTransport(
	ctx context.Context,
	w http.ResponseWriter,
	srcHeaders http.Header,
	upstream io.Reader,
	statusCode int,
	providerName string,
	adapter streaming.Adapter,
	engine *incrementalEngine,
) incrementalTransportResult {
	copyHeadersWithoutContentLength(w.Header(), srcHeaders)
	w.WriteHeader(statusCode)

	var buf bytes.Buffer
	teed := io.TeeReader(upstream, &buf)

	var (
		blocked            bool
		blockInspector     string
		blockReason        string
		sanitized          bool   // PR-F7.5
		sanitizedInspector string // PR-F7.5
	)

	decErr := adapter.Decoder.Decode(ctx, teed, func(ev streaming.Event) error {
		// Malformed chunk — инкремент metric, но продолжаем.
		if ev.Type == streaming.EventUnknownChunk {
			metrics.RecordStreamingMalformedChunk(providerName)
		}

		// PR-F7.2: inspection hook на delta_text. Block → emit
		// terminal error frame + sentinel для ранжи выхода. Flag
		// накапливается в engine; emit продолжается.
		if engine != nil && ev.Type == streaming.EventDeltaText && ev.Text != "" {
			v := engine.EvaluateDelta(ctx, ev.Text)
			if v.Block {
				metrics.RecordStreamingMidstreamBlock(providerName, v.InspectorName)
				// EmitError — transport primitive из F7.1 (provider-specific
				// terminal frame). Ошибка emit'а на этом этапе учитывается
				// как transport failure, но НЕ отменяет block intent
				// (block сохраняется в result).
				if emitErr := adapter.Emitter.EmitError(ctx, w, v.InspectorName, v.Reason); emitErr != nil {
					metrics.RecordStreamingEmitFail(providerName)
					// Не wrap'аем errMidstreamBlock сверху emitErr —
					// block важнее чем emit failure при его доставке.
				}
				blocked = true
				blockInspector = v.InspectorName
				blockReason = v.Reason
				return errMidstreamBlock
			}
			// v.Flag накапливается в engine; отдельной обработки
			// здесь не требуется.

			// PR-F7.5: sanitize path — replace delta content in emitted frame.
			if v.Sanitize {
				metrics.RecordStreamingSanitize(providerName, v.InspectorName)
				if emitErr := adapter.Emitter.EmitSanitized(ctx, w, ev, v.SanitizedText); emitErr != nil {
					metrics.RecordStreamingEmitFail(providerName)
					return fmt.Errorf("%w: %w", errTransportEmit, emitErr)
				}
				if !sanitized {
					sanitized = true
					sanitizedInspector = v.InspectorName
				}
				return nil // sanitized frame emitted; skip identity Emit below
			}
		}

		if emitErr := adapter.Emitter.Emit(ctx, w, ev); emitErr != nil {
			metrics.RecordStreamingEmitFail(providerName)
			return fmt.Errorf("%w: %w", errTransportEmit, emitErr)
		}
		return nil
	})

	res := incrementalTransportResult{
		Accumulated:        buf.Bytes(),
		Blocked:            blocked,
		BlockInspector:     blockInspector,
		BlockReason:        blockReason,
		Sanitized:          sanitized,
		SanitizedInspector: sanitizedInspector,
	}
	if engine != nil {
		res.Flagged = engine.Flagged()
		res.FlaggedInspector = engine.FlaggedInspector()
	}

	if decErr != nil {
		// 1. ctx cancel (client disconnect) → не фатальная ошибка.
		if ctx.Err() != nil {
			return res
		}
		// 2. mid-stream block sentinel — уже зафиксирован в res,
		// не считается transport error'ом (metric уже записан).
		if errors.Is(decErr, errMidstreamBlock) {
			return res
		}
		// 3. Emit-phase: metric уже записан внутри callback'а.
		// 4. Иначе — decoder fatal (upstream read / parser fatal).
		if !errors.Is(decErr, errTransportEmit) {
			metrics.RecordStreamingDecoderFatal(providerName)
		}
		res.TransportErr = decErr
	}
	return res
}

// shouldUseIncrementalStream — возвращает (adapter, useIncremental,
// fallbackReason). Contract:
//   - useIncremental=true: caller берёт incremental path;
//     fallbackReason пустой.
//   - useIncremental=false: caller остаётся на buffered branch.
//     fallbackReason заполнен одним из:
//       * FallbackReasonUnsupportedProvider (provider без adapter'а);
//       * reason из streamingCapability (CM+judge → "judge_inspector");
//       * пустая строка, если streamingMode != "incremental" (не
//         fallback, а обычный buffered-режим).
//     Caller обязан thread reason в local переменную и использовать
//     её при final audit write (compound marker
//     streaming_buffered_fallback:<original_action>).
//
// PR-F7.2 review fix: ранее reason хранился в мутируемом поле
// handler'а — data race при concurrent streaming requests. Теперь
// request-local: три return values.
func (h *Handler) shouldUseIncrementalStream(providerName string) (streaming.Adapter, bool, string) {
	if h.streamingMode != "incremental" {
		return streaming.Adapter{}, false, ""
	}
	a, ok := streaming.AdapterForProvider(providerName)
	if !ok {
		metrics.RecordStreamingFallback(providerName, FallbackReasonUnsupportedProvider)
		return streaming.Adapter{}, false, FallbackReasonUnsupportedProvider
	}
	if h.streamingCapability.IsFallback() {
		metrics.RecordStreamingFallback(providerName, h.streamingCapability.Reason)
		return streaming.Adapter{}, false, h.streamingCapability.Reason
	}
	return a, true, ""
}

// ---------------------------------------------------------------------------
// PR-F7.5: STREAMING_ALLOW_INCREMENTAL_IN_PROD — promotion criteria
// ---------------------------------------------------------------------------
//
// The STREAMING_ALLOW_INCREMENTAL_IN_PROD gate remains active after F7.5.
// It exists to prevent accidental production opt-in before the incremental
// path has proven sufficient stability. Do NOT remove or bypass this gate
// until ALL of the following criteria are met:
//
//  1. Error budget: streaming_emit_fail_total + streaming_decoder_fatal_total
//     rate(1h) < 0.1% of total streaming requests for ≥ 30 consecutive days.
//
//  2. Fallback rate: streaming_fallback_total (reason=unsupported_provider)
//     is zero or negligible for all target providers.
//
//  3. Sanitize correctness: shadowai_streaming_midstream_sanitize_total
//     monitored in shadow mode for ≥ 30 days; zero false-positive sanitize
//     events on non-PII content confirmed by audit sample review.
//
//  4. Bytes-identity verification: TestRoundTrip_BytesIdentity passes in
//     CI on the exact version being promoted; no adapter regression.
//
//  5. Provider coverage: all providers used in production have a full
//     (not stub) EmitSanitized implementation, OR incremental is limited
//     to OpenAI-compat providers only via config.
//
//  6. Operator sign-off: security team and platform lead have reviewed
//     streaming sanitize audit samples from shadow mode.
//
// Current F7.5 status: criteria 5 is NOT fully met (Anthropic/Gemini/Ollama
// use identity-stub EmitSanitized). Production rollout for those providers
// requires F7.6+ full implementation.
//
// composeBufferedFallbackMarker: удалён в PR-F7.3. Заменён на
// structured outcome/fallback_reason fields в domain.AuditLog
// (см. streaming_audit.go Outcome* + classifyBufferedOutcome).

package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/shadowai/backend/internal/metrics"
	"github.com/shadowai/backend/internal/proxy/streaming"
)

// PR-F7.1 audit markers для incremental mode. Явные строки, чтобы
// ops-дашборды могли queriify "какие стримы ушли через incremental
// без full enforcement".
//
//   PolicyActionStreamingBudgetExceededSoft — post-call budget check
//   вернул over-budget, но body уже ушёл клиенту. В buffered режиме
//   это был бы 402 с блоком body; в incremental (F7.1) audit пишется
//   с этим маркером + RecordBudgetBlock инкрементит счётчик для
//   последующих запросов.
//
//   PolicyActionStreamingTransportError — decoder или emitter упал
//   на non-cancel error (ctx.Err client-disconnect-like → не считается
//   transport error'ом и пишется как allow). В audit отражается как
//   502 Bad Gateway + этот маркер, чтобы отличать от успешного
//   stream'а. Buffered path в аналогичной ситуации (io.ReadAll err)
//   возвращает 502 клиенту и audit не пишет — incremental теперь
//   честнее в audit footprint.
const (
	PolicyActionStreamingBudgetExceededSoft = "streaming_budget_exceeded_soft"
	PolicyActionStreamingTransportError     = "streaming_transport_error"
)

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
) (accumulated []byte, err error) {
	copyHeadersWithoutContentLength(w.Header(), srcHeaders)
	w.WriteHeader(statusCode)

	var buf bytes.Buffer
	// tee: upstream → (buf для accounting/audit) + параллельный
	// decoder. decoder читает из tee, так что всё, что он потребил,
	// остаётся в buf.
	teed := io.TeeReader(upstream, &buf)

	decErr := adapter.Decoder.Decode(ctx, teed, func(ev streaming.Event) error {
		// Malformed chunk — инкремент metric, но продолжаем (identity
		// passthrough сохраняется: emitter запишет RawBytes).
		if ev.Type == streaming.EventUnknownChunk {
			// Различаем: keepalive comment'ы (OpenRouter "OPENROUTER
			// PROCESSING") эмитят unknown_chunk тоже. Для F7.1
			// считаем все unknown_chunk'и как "malformed" для
			// метрики; F7.2 может разделить keepalive vs error.
			metrics.RecordStreamingMalformedChunk(providerName)
		}
		if emitErr := adapter.Emitter.Emit(ctx, w, ev); emitErr != nil {
			metrics.RecordStreamingEmitFail(providerName)
			return emitErr
		}
		return nil
	})
	if decErr != nil {
		// ctx cancel (client disconnect) → не фатальная ошибка с
		// точки зрения caller'а, но accumulated buf всё равно
		// возвращаем — audit напишет partial data.
		if ctx.Err() != nil {
			return buf.Bytes(), nil
		}
		return buf.Bytes(), decErr
	}
	return buf.Bytes(), nil
}

// shouldUseIncrementalStream — возвращает (adapter, true) если можно
// использовать F7.1 incremental path для данного provider'а. False
// означает: caller должен остаться на buffered branch и инкрементить
// соответствующий fallback metric.
func (h *Handler) shouldUseIncrementalStream(providerName string) (streaming.Adapter, bool) {
	if h.streamingMode != "incremental" {
		return streaming.Adapter{}, false
	}
	a, ok := streaming.AdapterForProvider(providerName)
	if !ok {
		metrics.RecordStreamingFallback(providerName, "unsupported_provider")
		return streaming.Adapter{}, false
	}
	return a, true
}

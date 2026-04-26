package proxy

import (
	"bytes"
	"context"
	"net/http/httptest"
	"time"

	"github.com/shadowai/backend/internal/metrics"
	"github.com/shadowai/backend/internal/proxy/streaming"
)

// ShadowCompareResult — результат сравнения buffered vs incremental
// для STREAMING_MODE=shadow. Buffered path остаётся единственным
// source of truth; shadow только наблюдает и сравнивает.
type ShadowCompareResult struct {
	// Match — true если оба пути дали одинаковые outcomes.
	Match bool
	// Mismatches — список несовпавших полей (for logging/metrics).
	Mismatches []ShadowMismatch
	// IncrementalOutcome — что дал incremental pipeline.
	IncrementalOutcome string
	// IncrementalPolicyAction — security verdict incremental'а.
	IncrementalPolicyAction string
	// IncrementalUsageSource — usage source incremental'а.
	IncrementalUsageSource string
	// FallbackReason — если capability потребовала fallback на buffered.
	FallbackReason string
}

// ShadowMismatch — одна несовпавшая пара.
type ShadowMismatch struct {
	Kind     string // policy_action|outcome|usage_source|fallback_reason|transport_error
	Buffered string
	Shadow   string
}

// runShadowCompare — sequential shadow compare (Q1: A). Принимает
// уже накопленный buffered response (respBytes из io.ReadAll), прогоняет
// incremental engine in-memory и сравнивает с buffered result'ом.
//
// Вызывается после buffered audit write — buffered truth уже зафиксирована.
// Shadow НЕ меняет client-visible поведение и НЕ пишет в audit_logs.
// Расхождения идут только в metrics + app log.
//
// Параметры:
//   ctx — request context (honors cancellation).
//   respBytes — полный response body (уже прочитанный buffered path'ом).
//   providerName — для metrics labels и AdapterForProvider.
//   bufferedOutcome, bufferedPolicyAction, bufferedUsageSource — verdicts
//     уже записанные в audit_logs по buffered truth.
//   h — handler (для доступа к firewallPipeline, dlpSvc, streamingCapability).
//   model, userID — для inspection engine payload.
func (h *Handler) runShadowCompare(
	ctx context.Context,
	respBytes []byte,
	providerName string,
	model, userID string,
	provider Provider,
	bufferedOutcome, bufferedPolicyAction, bufferedUsageSource string,
) ShadowCompareResult {
	// 1. Capability check — даже в shadow mode мы должны знать
	// попал бы этот stream в buffered_fallback при incremental.
	if h.streamingCapability.IsFallback() {
		metrics.RecordStreamingShadowFallback(providerName, h.streamingCapability.Reason)
		r := ShadowCompareResult{
			FallbackReason: h.streamingCapability.Reason,
		}
		// Если buffered outcome был stream_buffered_fallback, это match.
		if bufferedOutcome == OutcomeStreamBufferedFallback {
			r.Match = true
		} else {
			r.Match = false
			r.Mismatches = append(r.Mismatches, ShadowMismatch{
				Kind:     "fallback_reason",
				Buffered: bufferedOutcome,
				Shadow:   OutcomeStreamBufferedFallback + ":" + h.streamingCapability.Reason,
			})
		}
		return r
	}

	// 2. Adapter lookup.
	adapter, ok := streaming.AdapterForProvider(providerName)
	if !ok {
		// provider unsupported for incremental — shadow fallback.
		metrics.RecordStreamingShadowFallback(providerName, FallbackReasonUnsupportedProvider)
		return ShadowCompareResult{FallbackReason: FallbackReasonUnsupportedProvider, Match: false}
	}

	// 3. Incremental pipeline in-memory (sequential — на respBytes).
	// Используем discardWriter для emit — мы только запускаем inspection,
	// результат клиенту не отдаётся.
	shadowW := httptest.NewRecorder()
	shadowEngine := newIncrementalEngine(h.firewallPipeline, h.dlpSvc, model, providerName, userID)
	res := h.runIncrementalStreamTransport(
		ctx, shadowW, nil, bytes.NewReader(respBytes),
		200, providerName, adapter, shadowEngine,
	)

	// 4. Parse usage from shadow result (same bytes, shadow perspective).
	// Note (PR-F7.4.1 review fix): использовать providerName без суффикса
	// чтобы не размывать cardinality метрики — контракт
	// RecordStreamUsageParseFail ожидает реальное provider имя.
	shadowStreamUsage, shadowParseErr := parseStreamingUsage(provider, res.Accumulated, model)
	if shadowParseErr != nil || !shadowStreamUsage.Found {
		metrics.RecordStreamUsageParseFail(providerName)
	}

	// 5. Classify incremental outcomes.
	overBudget := false // shadow не делает budget check
	shadowOutcome := classifyIncrementalOutcome(
		res.Blocked, res.TransportErr != nil, shadowParseErr, overBudget, res.Flagged)
	shadowPolicyAction := incrementalSecurityVerdict("allowed", res.Blocked, res.Sanitized, res.Flagged)
	// Shadow stream в memory завершится как completed если incremental не блокировал.
	shadowCompleted := shadowOutcome == OutcomeStreamCompleted
	shadowUsageSource := classifyUsageSource(shadowStreamUsage, shadowParseErr, shadowCompleted)

	// 6. Compare.
	var mismatches []ShadowMismatch
	if shadowOutcome != bufferedOutcome {
		mismatches = append(mismatches, ShadowMismatch{
			Kind:     "outcome",
			Buffered: bufferedOutcome,
			Shadow:   shadowOutcome,
		})
		metrics.RecordStreamingShadowMismatch(providerName, "outcome")
	}
	if shadowPolicyAction != bufferedPolicyAction {
		mismatches = append(mismatches, ShadowMismatch{
			Kind:     "policy_action",
			Buffered: bufferedPolicyAction,
			Shadow:   shadowPolicyAction,
		})
		metrics.RecordStreamingShadowMismatch(providerName, "policy_action")
	}
	if shadowUsageSource != bufferedUsageSource {
		mismatches = append(mismatches, ShadowMismatch{
			Kind:     "usage_source",
			Buffered: bufferedUsageSource,
			Shadow:   shadowUsageSource,
		})
		metrics.RecordStreamingShadowMismatch(providerName, "usage_source")
	}
	if (res.TransportErr != nil) != (bufferedOutcome == OutcomeStreamTransportError) {
		mismatches = append(mismatches, ShadowMismatch{
			Kind:     "transport_error",
			Buffered: bufferedOutcome,
			Shadow:   shadowOutcome,
		})
		metrics.RecordStreamingShadowMismatch(providerName, "transport_error")
	}

	_ = time.Now() // suppress unused import if needed

	result := ShadowCompareResult{
		Match:                   len(mismatches) == 0,
		Mismatches:              mismatches,
		IncrementalOutcome:      shadowOutcome,
		IncrementalPolicyAction: shadowPolicyAction,
		IncrementalUsageSource:  shadowUsageSource,
	}

	if result.Match {
		metrics.RecordStreamingShadowCompare(providerName, "match")
	} else {
		metrics.RecordStreamingShadowCompare(providerName, "mismatch")
	}
	return result
}

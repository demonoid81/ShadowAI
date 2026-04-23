package proxy

// PR-F7.3: structured streaming audit vocabulary. Заменяет compound
// PolicyAction hack из PR-F7.2.1. Invariant (RFC §11, architecture
// rule):
//
//   policy_action    — policy/security verdict (allowed/blocked/
//                      flagged/sanitized). НЕ содержит
//                      transport/accounting семантики.
//   outcome          — transport-level итог streaming-запроса.
//   fallback_reason  — почему incremental не применён. Non-empty
//                      ТОЛЬКО при outcome=stream_buffered_fallback.
//   usage_source     — origin accounting data.
//
// Пустой outcome означает "non-streaming" (chatReq.Stream=false) или
// request-side early reject (stream machinery не запускалась).

// Streaming outcome словарь. Значения — stable identifiers для
// dashboards / SIEM rules; не переименовывать без breaking-change
// announcement.
const (
	// OutcomeStreamCompleted — stream завершился нормально до
	// natural EOF. Применяется и для incremental (все chunks
	// прошли inspection), и для buffered-режима (без fallback'а и
	// без block'а).
	OutcomeStreamCompleted = "stream_completed"

	// OutcomeStreamFlagged — stream прошёл до конца, но был
	// помечен flag'ом (response-side firewall/DLP вернул Flag
	// или Sanitize-downgrade'нутый до Flag в F7.2).
	OutcomeStreamFlagged = "stream_flagged"

	// OutcomeStreamBlocked — buffered path заблокировал stream
	// после чтения upstream, но до emit'а клиенту. Client получил
	// 403 + JSON error без stream body. Stream machinery была
	// invoked (upstream прочитан, inspectors бегали), но bytes
	// до клиента не дошли.
	OutcomeStreamBlocked = "stream_blocked"

	// OutcomeStreamBlockedMidflight — incremental path заблокировал
	// stream ПОСЛЕ начала emit'а. Client получил partial bytes +
	// SSE/NDJSON terminal error frame. Отличается от
	// stream_blocked семантикой "клиент уже видел часть ответа".
	OutcomeStreamBlockedMidflight = "stream_blocked_midflight"

	// OutcomeStreamBufferedFallback — incremental был requested, но
	// capability / unsupported provider заставили buffered path.
	// FallbackReason всегда non-empty; policy_action отражает
	// buffered-path verdict (allowed/blocked/flagged/sanitized).
	OutcomeStreamBufferedFallback = "stream_buffered_fallback"

	// OutcomeStreamTransportError — decoder или emitter упал на
	// non-cancel error. audit StatusCode=502. Metric:
	// streaming_emit_fail_total (emit-phase) или
	// streaming_decoder_fatal_total (decoder-phase).
	OutcomeStreamTransportError = "stream_transport_error"

	// OutcomeStreamUsageParseFailed — transport ok, но
	// parseStreamingUsage вернул err (parser fatal на usage
	// frames). Отличается от "usage не найден, но parse ok":
	// второй случай → outcome=stream_completed, usage_source=none.
	OutcomeStreamUsageParseFailed = "stream_usage_parse_failed"

	// OutcomeStreamBudgetExceededSoft — incremental path: post-call
	// budget check вернул over-budget, но body уже ушёл клиенту
	// (в buffered было бы hard 402 + block). Soft-record'им;
	// RecordBudgetBlock инкрементит для следующих запросов.
	OutcomeStreamBudgetExceededSoft = "stream_budget_exceeded_soft"
)

// UsageSource — откуда взялась accounting truth.
const (
	// UsageSourceFinal — provider прислал полный usage report
	// (Found=true и parse успешен).
	UsageSourceFinal = "final"

	// UsageSourceNone — usage отсутствует. Либо Found=false
	// (provider не прислал), либо parseErr != nil (parser упал).
	// RecordUsage не вызывается.
	UsageSourceNone = "none"

	// UsageSourcePartial — reserved для F7.4. Значение означает
	// "provider прислал intermediate usage (Anthropic
	// message_delta с cumulative output_tokens) но не финальный
	// message_stop" — то есть accounting извлечён из partial
	// stream.
	//
	// F7.3: parser'ы не различают partial vs final. Этот
	// константа зарезервирована для F7.4, который расширит
	// StreamUsage дополнительным полем. В F7.3 этот const НЕ
	// возвращается classifyUsageSource — только final или none.
	UsageSourcePartial = "partial"
)

// classifyUsageSource — F7.3 implementation. Различает только
// final vs none. Partial — reserved, см. const above.
func classifyUsageSource(found bool, parseErr error) string {
	if parseErr != nil {
		return UsageSourceNone
	}
	if !found {
		return UsageSourceNone
	}
	return UsageSourceFinal
}

// classifyIncrementalOutcome — приоритетная классификация для
// incremental path. Правила (в порядке приоритета):
//
//  1. res.Blocked    → stream_blocked_midflight (inspector midstream).
//  2. res.TransportErr != nil → stream_transport_error.
//  3. parseErr != nil → stream_usage_parse_failed (usage parser fatal;
//     usage Found=false без error НЕ попадает сюда — даёт
//     stream_completed + usage_source=none).
//  4. overBudget (budget soft-exceed после accounting) →
//     stream_budget_exceeded_soft.
//  5. res.Flagged   → stream_flagged.
//  6. otherwise     → stream_completed.
func classifyIncrementalOutcome(blocked, transportErr bool, parseErr error, overBudget, flagged bool) string {
	switch {
	case blocked:
		return OutcomeStreamBlockedMidflight
	case transportErr:
		return OutcomeStreamTransportError
	case parseErr != nil:
		return OutcomeStreamUsageParseFailed
	case overBudget:
		return OutcomeStreamBudgetExceededSoft
	case flagged:
		return OutcomeStreamFlagged
	default:
		return OutcomeStreamCompleted
	}
}

// classifyBufferedOutcome — для buffered path (включая fallback
// случай). Приоритет:
//
//  1. fallbackFromIncremental → stream_buffered_fallback (выше
//     остальных — operators видят "fallback произошёл" независимо
//     от того, что дальше случилось в buffered-логике; конкретное
//     policy_verdict дублирует через policy_action).
//  2. policyAction=="blocked" → stream_blocked.
//  3. policyAction=="flagged" → stream_flagged.
//  4. parseErr != nil → stream_usage_parse_failed.
//  5. otherwise (including "sanitized", "allowed") → stream_completed.
//
// Обоснование для "sanitized" → stream_completed: sanitize — это
// policy modification, stream как transport artifact завершился
// нормально. policy_action=sanitized передаёт "what" policy сделала,
// outcome=stream_completed говорит "transport layer отработал".
// bufferedBudgetBlockOutcome — outcome для buffered hard-budget
// block (client получает 402, body не отдаётся). Если stream был
// fallback'нут из incremental — stream_buffered_fallback доминирует;
// иначе stream_blocked.
func bufferedBudgetBlockOutcome(fallbackFromIncremental bool) string {
	if fallbackFromIncremental {
		return OutcomeStreamBufferedFallback
	}
	return OutcomeStreamBlocked
}

func classifyBufferedOutcome(policyAction string, fallbackFromIncremental bool, parseErr error) string {
	if fallbackFromIncremental {
		return OutcomeStreamBufferedFallback
	}
	switch policyAction {
	case "blocked":
		return OutcomeStreamBlocked
	case "flagged":
		return OutcomeStreamFlagged
	}
	if parseErr != nil {
		return OutcomeStreamUsageParseFailed
	}
	return OutcomeStreamCompleted
}

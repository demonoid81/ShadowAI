package proxy

import (
	"github.com/shadowai/backend/internal/firewall"
)

// StreamingCapability — результат capability-проверки для incremental
// streaming. Определяется при wire-time (SetStreamingMode) на основе
// конфигурации firewall.Pipeline.
//
// PR-F7.2: классификация ограничена двумя значениями — incremental
// или buffered_fallback. Sanitize в F7.2 НЕ поддерживается (см.
// explicit scope): sanitize-возможные inspector'ы, если появятся,
// трактуются как flag.
type StreamingCapability int

const (
	// CapabilityIncremental — все активные response-side inspector'ы
	// pattern-based и могут работать на sliding window без обращения
	// к external LLM / embedding сервисам.
	CapabilityIncremental StreamingCapability = iota
	// CapabilityBufferedFallback — один из inspector'ов требует
	// full-text context или вызывает external LLM в response path
	// (текущий known case: content_moderation + judge.Enabled=true).
	// Весь stream для такого deployment'а идёт через buffered path.
	CapabilityBufferedFallback
)

// CapabilityDecision — pair (Capability, Reason). Reason обязателен
// при CapabilityBufferedFallback — он попадает в
// streaming_fallback_total{reason} и в audit marker.
type CapabilityDecision struct {
	Capability StreamingCapability
	Reason     string
}

// IsFallback возвращает true если весь stream должен идти через
// buffered path вместо incremental.
func (d CapabilityDecision) IsFallback() bool {
	return d.Capability == CapabilityBufferedFallback
}

// Известные причины buffered_fallback. Значения стабильны — они
// используются как prometheus label value (низкая cardinality).
const (
	FallbackReasonJudgeInspector       = "judge_inspector"
	FallbackReasonUnsupportedProvider  = "unsupported_provider"
	FallbackReasonUnsupportedInspector = "unsupported_inspector"
)

// DecideStreamingCapability проверяет firewall.Pipeline на наличие
// inspector'ов, несовместимых с incremental response streaming.
//
// Логика (RFC §12.6):
//   - content_moderation с judge.Enabled=true → fallback
//     (mid-stream judge вызов = латентность + cost; буферизуем целиком,
//     чтобы не сделать silent safety regression).
//   - остальные response-side inspectors (pii, dlp, output_validation,
//     content_moderation без judge) → incremental-safe.
//   - request-only inspectors (semantic, semantic_v2, jailbreak,
//     prompt_injection, policy, multiturn, content_ratelimit) не
//     влияют на response streaming — их capability не проверяется.
//
// nil pipeline → CapabilityIncremental (нет проверок, нет fallback'а).
func DecideStreamingCapability(p *firewall.Pipeline) CapabilityDecision {
	if p == nil {
		return CapabilityDecision{Capability: CapabilityIncremental}
	}
	for _, s := range p.Status() {
		// CM + judge enabled → fallback. Применимо только если
		// inspector сам enabled. Phase=="both" у CM — он работает и
		// на request, и на response; если judge активен, response-side
		// inspection неизбежно может триггернуть Evaluate.
		if s.Name == "content_moderation" && s.Enabled && s.JudgeInfo != nil && s.JudgeInfo.Enabled {
			return CapabilityDecision{
				Capability: CapabilityBufferedFallback,
				Reason:     FallbackReasonJudgeInspector,
			}
		}
	}
	return CapabilityDecision{Capability: CapabilityIncremental}
}

package proxy

import (
	"context"

	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/firewall"
	"github.com/shadowai/backend/internal/pii"
	"github.com/shadowai/backend/internal/proxy/streaming"
)

// incrementalVerdict — результат одной chunk-level оценки. Поля
// flag'ами (не enum), чтобы caller мог независимо накапливать flag
// состояние и при этом видеть terminal block или sanitize.
type incrementalVerdict struct {
	// Block — inspector велел прервать stream. Caller должен:
	//   1) emitter.EmitError(...)
	//   2) upstream cancel (resp.Body.Close / context cancel)
	//   3) audit с PolicyAction=streaming_blocked_midflight.
	Block bool
	// Sanitize — PR-F7.5: inspector потребовал замену текста delta.
	// SanitizedText содержит очищенную версию. Caller вызывает
	// emitter.EmitSanitized вместо обычного Emit.
	// Sanitize и Block взаимоисключаются — Block имеет приоритет.
	Sanitize      bool
	SanitizedText string
	// Flag — inspector пометил chunk как подозрительный; stream
	// продолжается. Caller накапливает в stream-level flag состояние.
	Flag bool
	// InspectorName — имя inspector'а, принявшего решение. Для
	// Block/Sanitize/Flag. Empty при Allow.
	InspectorName string
	// Reason — человекочитаемая причина (для audit / error frame).
	Reason string
}

// incrementalEngine — инкрементальный аналог buffered-pipeline'а
// в handler.go ProxyChat/UnifiedChat. Вызывается на каждый
// delta_text event'е.
//
// Responsibilities:
//   - Поддерживать sliding window через streaming.InspectionWindow.
//   - Вызывать firewall.Pipeline.InspectResponse на window.
//   - Вызывать pii.Scan + dlp.Service на window.
//   - Аггрегировать решения в incrementalVerdict.
//
// Non-responsibilities (F7.2 explicit):
//   - не делает sanitize;
//   - не принимает решения о buffered_fallback (это сделано на wire-time
//     через DecideStreamingCapability);
//   - не пишет audit / metrics — это задача caller'а (handler).
type incrementalEngine struct {
	firewallPipeline *firewall.Pipeline
	dlpSvc           *dlp.Service
	window           *streaming.InspectionWindow

	// context для firewall.Payload (Model/Provider/UserID) — заполняется
	// из upstream request'а один раз на stream.
	model    string
	provider string
	userID   string

	// flagged — stream-level flag persistence. Если один delta был
	// flagged, вся audit-запись остаётся flagged (соответствует
	// buffered поведению).
	flagged          bool
	flaggedInspector string

	// sanitized — PR-F7.5: stream-level sanitize persistence.
	// Если хотя бы один delta был sanitized, audit PolicyAction=sanitized.
	sanitized          bool
	sanitizedInspector string
}

// newIncrementalEngine создаёт engine с default inspection window.
// firewallPipeline / dlpSvc могут быть nil — engine просто пропустит
// соответствующие inspection-ветки.
func newIncrementalEngine(
	firewallPipeline *firewall.Pipeline,
	dlpSvc *dlp.Service,
	model, provider, userID string,
) *incrementalEngine {
	return &incrementalEngine{
		firewallPipeline: firewallPipeline,
		dlpSvc:           dlpSvc,
		window:           streaming.NewInspectionWindow(),
		model:            model,
		provider:         provider,
		userID:           userID,
	}
}

// EvaluateDelta инспектирует новый chunk text. Возвращает verdict,
// по которому caller решает emit vs block.
//
// F7.2 invariant: delta добавляется в window БЕФОРЕ inspection, так
// чтобы cross-chunk patterns (secret из 2+ frame'ов) попадались.
func (e *incrementalEngine) EvaluateDelta(ctx context.Context, delta string) incrementalVerdict {
	if delta == "" {
		return incrementalVerdict{}
	}
	e.window.Append(delta)
	text := e.window.Window()

	// 1. Firewall pipeline — response phase.
	if e.firewallPipeline != nil {
		fwPayload := &firewall.Payload{
			Text:     text,
			Model:    e.model,
			Provider: e.provider,
			UserID:   e.userID,
			Phase:    firewall.PhaseResponse,
		}
		decision, err := e.firewallPipeline.InspectResponse(ctx, fwPayload)
		if err != nil {
			// RFC §12.1 fail-mode matrix: response-side inspector'ы
			// (OutputValidation, PII, DLP, ContentModeration-heuristic,
			// Policy) — все safety-critical, fail-closed. Semantic /
			// SemanticV2 (fail-open) — request-only, в response path
			// их не бывает. Значит blanket fail-closed = корректный
			// mapping матрицы для incremental response engine.
			//
			// Previous F7.2 behavior (blanket fail-open) расходился с
			// RFC § и давал silent safety regression при transient
			// inspector errors. Review fix.
			return incrementalVerdict{
				Block:         true,
				InspectorName: "firewall_pipeline_error",
				Reason:        "inspector error (fail-closed per RFC §12.1)",
			}
		}
		if decision != nil {
			switch decision.Action {
			case firewall.ActionBlock:
				return incrementalVerdict{
					Block:         true,
					InspectorName: decision.InspectorName,
					Reason:        decision.Reason,
				}
			case firewall.ActionFlag:
				e.flagged = true
				if e.flaggedInspector == "" {
					e.flaggedInspector = decision.InspectorName
				}
			case firewall.ActionSanitize:
				// PR-F7.5: sanitize the current DELTA (not the window).
				// The window triggered the pattern but we replace only
				// the current delta content in the emitted frame.
				// Cross-chunk PII spanning multiple deltas → F7.6 scope.
				if e.dlpSvc != nil {
					deltaFindings := pii.Scan(delta)
					sanitizedDelta := e.dlpSvc.Sanitize(delta, deltaFindings)
					e.sanitized = true
					if e.sanitizedInspector == "" {
						e.sanitizedInspector = decision.InspectorName
					}
					return incrementalVerdict{
						Sanitize:      true,
						SanitizedText: sanitizedDelta,
						InspectorName: decision.InspectorName,
					}
				}
				// No DLP service: downgrade to flag (can't re-encode without sanitizer).
				e.flagged = true
				if e.flaggedInspector == "" {
					e.flaggedInspector = decision.InspectorName
				}
			}
		}
	}

	// 2. DLP + PII on window (pattern-based, incremental-safe).
	if e.dlpSvc != nil {
		findings := pii.Scan(text)
		dec := e.dlpSvc.Evaluate(text, findings)
		switch dec.Action {
		case dlp.DLPActionBlock:
			return incrementalVerdict{
				Block:         true,
				InspectorName: "dlp",
				Reason:        dec.Reason,
			}
		case dlp.DLPActionSanitize:
			// PR-F7.5: sanitize the current delta.
			deltaFindings := pii.Scan(delta)
			sanitizedDelta := e.dlpSvc.Sanitize(delta, deltaFindings)
			e.sanitized = true
			if e.sanitizedInspector == "" {
				e.sanitizedInspector = "dlp"
			}
			return incrementalVerdict{
				Sanitize:      true,
				SanitizedText: sanitizedDelta,
				InspectorName: "dlp",
			}
		}
	}

	if e.flagged {
		return incrementalVerdict{
			Flag:          true,
			InspectorName: e.flaggedInspector,
		}
	}
	return incrementalVerdict{}
}

// Flagged возвращает накопленный stream-level flag state (true если
// хотя бы один EvaluateDelta вернул flag за всё время stream'а).
func (e *incrementalEngine) Flagged() bool {
	return e.flagged
}

// FlaggedInspector возвращает имя первого inspector'а, который
// поставил flag на этот stream. Empty если Flagged()==false.
func (e *incrementalEngine) FlaggedInspector() string {
	return e.flaggedInspector
}

// Sanitized возвращает true если хотя бы один delta был sanitized
// (PR-F7.5).
func (e *incrementalEngine) Sanitized() bool { return e.sanitized }

// SanitizedInspector возвращает имя первого inspector'а, который
// вернул sanitize verdict. Empty если Sanitized()==false.
func (e *incrementalEngine) SanitizedInspector() string { return e.sanitizedInspector }

// Accumulated возвращает всё, что было пропущено через window, для
// post-stream audit (подпрограммы, которые хотят scan полного текста
// уже по окончании stream'а).
func (e *incrementalEngine) Accumulated() string {
	return e.window.Accumulated()
}

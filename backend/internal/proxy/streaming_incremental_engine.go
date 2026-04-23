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
// состояние и при этом видеть terminal block.
//
// PR-F7.2 ограничение scope'а: sanitize НЕ поддерживается. Если
// inspector возвращает ActionSanitize, engine трактует его как flag
// (stream продолжается без модификации, audit получает flag).
// Sanitize вернётся в F7.3/F7.4 после доказанной корректности.
type incrementalVerdict struct {
	// Block — inspector велел прервать stream. Caller должен:
	//   1) emitter.EmitError(...)
	//   2) upstream cancel (resp.Body.Close / context cancel)
	//   3) audit с PolicyAction=streaming_blocked_midflight.
	Block bool
	// Flag — inspector пометил chunk как подозрительный; stream
	// продолжается. Caller накапливает в stream-level flag состояние.
	Flag bool
	// InspectorName — имя inspector'а, принявшего решение. Для
	// Block/Flag. Empty при Allow.
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
	flagged           bool
	flaggedInspector  string
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
		// Fail-open на error: F7.2 conservative default, не рвём
		// stream из-за transient inspector ошибки. Эта политика
		// зафиксирована в RFC §12.1 / §12.5 (inspector timeout
		// mapping отдельно от HTTP request timeout).
		if err == nil && decision != nil {
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
				// F7.2 scope limit: sanitize НЕ поддерживается mid-stream.
				// Downgrade до flag — stream продолжается без
				// модификации, audit отражает flag.
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
			// Downgrade до flag (см. выше). В dlp.Service нет
			// отдельного DLPActionFlag — sanitize это ближайший
			// "мягкий" сигнал.
			e.flagged = true
			if e.flaggedInspector == "" {
				e.flaggedInspector = "dlp"
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

// Accumulated возвращает всё, что было пропущено через window, для
// post-stream audit (подпрограммы, которые хотят scan полного текста
// уже по окончании stream'а).
func (e *incrementalEngine) Accumulated() string {
	return e.window.Accumulated()
}

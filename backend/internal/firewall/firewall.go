package firewall

import (
	"context"

	"github.com/shadowai/backend/internal/metrics"
)

type Phase string

const (
	PhaseRequest  Phase = "request"
	PhaseResponse Phase = "response"
)

type Action string

const (
	ActionAllow    Action = "allow"
	ActionBlock    Action = "block"
	ActionSanitize Action = "sanitize"
	ActionFlag     Action = "flag"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Finding struct {
	Type     string            `json:"type"`
	Severity Severity          `json:"severity"`
	Match    string            `json:"match"`
	Start    int               `json:"start"`
	End      int               `json:"end"`
	Meta     map[string]string `json:"meta,omitempty"`
}

// ShadowDecision — наблюдение shadow-инспектора, приложенное к
// финальному Decision для audit-записи. В отличие от Finding'ов, не
// участвует в enforcement: handler записывает массив в
// audit_logs.shadow_decisions_json и продолжает обычный request-flow.
//
// Namespace полей минимален умышленно (PR-4 MVP): inspector+action+reason+severity.
// Findings-payload НЕ включаем, чтобы не раздувать audit row — операторы
// при необходимости достанут детали из логов инспектора.
type ShadowDecision struct {
	Inspector string   `json:"inspector"`
	Action    Action   `json:"action"`
	Reason    string   `json:"reason,omitempty"`
	Severity  Severity `json:"severity,omitempty"`
}

type Decision struct {
	Action        Action    `json:"action"`
	Reason        string    `json:"reason"`
	Severity      Severity  `json:"severity"`
	Findings      []Finding `json:"findings"`
	InspectorName string    `json:"inspector_name"`
	// SanitizedText непусто только когда Action == ActionSanitize.
	// Содержит очищенную версию исходного текста.
	SanitizedText string `json:"sanitized_text,omitempty"`
	// ShadowDecisions — наблюдения инспекторов, работавших в ModeShadow.
	// Пуст в стандартном enforce-пайплайне. Заполняется pipeline.run().
	ShadowDecisions []ShadowDecision `json:"shadow_decisions,omitempty"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Payload struct {
	Text     string
	Messages []Message
	Model    string
	Provider string
	UserID   string
	Phase    Phase
	Meta     map[string]string
}

type Inspector interface {
	Name() string
	InspectRequest(ctx context.Context, p *Payload) (*Decision, error)
	InspectResponse(ctx context.Context, p *Payload) (*Decision, error)
}

// pipelineEntry связывает зарегистрированный инспектор с его runtime-
// режимом. Не public: код вне пакета работает с Pipeline через
// Register* / Inspect* / Status().
//
// Причина private struct (а не public wrapper): Status() в status.go
// делает type-switch на concrete Inspector type, а wrapper сломал бы
// все case-ветки, требуя unwrap'а в каждой.
type pipelineEntry struct {
	inspector Inspector
	mode      InspectorMode
}

type Pipeline struct {
	entries []pipelineEntry
	modes   *InspectorModes
}

// NewPipeline создаёт пайплайн без пер-инспекторной настройки режимов.
// Все зарегистрированные инспекторы будут работать в ModeEnforce
// (backward compat для call-site'ов, которые не знают про PR-4).
func NewPipeline() *Pipeline {
	return &Pipeline{}
}

// NewPipelineWithModes принимает предзагруженную конфигурацию режимов.
// Вызывается в main.go после config.Load() + LoadInspectorModesFromEnv().
func NewPipelineWithModes(modes *InspectorModes) *Pipeline {
	return &Pipeline{modes: modes}
}

// Register добавляет инспектор. Режим резолвится из p.modes по имени
// (Inspector.Name()) один раз при регистрации: повторный resolve при
// каждом запросе не имеет смысла (modes иммутабельны в runtime).
func (p *Pipeline) Register(i Inspector) {
	mode := p.modes.For(i.Name())
	p.entries = append(p.entries, pipelineEntry{inspector: i, mode: mode})
}

func (p *Pipeline) InspectRequest(ctx context.Context, payload *Payload) (*Decision, error) {
	return p.run(ctx, payload, func(i Inspector) func(context.Context, *Payload) (*Decision, error) {
		return i.InspectRequest
	})
}

func (p *Pipeline) InspectResponse(ctx context.Context, payload *Payload) (*Decision, error) {
	return p.run(ctx, payload, func(i Inspector) func(context.Context, *Payload) (*Decision, error) {
		return i.InspectResponse
	})
}

func (p *Pipeline) run(
	ctx context.Context,
	payload *Payload,
	fn func(Inspector) func(context.Context, *Payload) (*Decision, error),
) (*Decision, error) {
	var allFindings []Finding
	var shadowDecisions []ShadowDecision
	highestSeverity := SeverityLow
	finalAction := ActionAllow
	var finalReason string
	var finalInspectorName string
	var finalSanitizedText string

	for _, entry := range p.entries {
		// ModeDisabled: инспектор не исполняется вообще — ни вызова,
		// ни метрики. Это семантически идентично "не зарегистрирован".
		if entry.mode == ModeDisabled {
			continue
		}

		d, err := fn(entry.inspector)(ctx, payload)
		if err != nil {
			return nil, err
		}
		if d == nil {
			continue
		}

		d.InspectorName = entry.inspector.Name()

		// Метрика пишется для enforce И shadow. Label mode различает.
		metrics.RecordFirewallDecision(
			string(payload.Phase),
			d.InspectorName,
			string(d.Action),
			string(entry.mode),
		)

		// ModeShadow: observational only. Никакой мутации pipeline-state:
		//   - не блокирует (нет return на ActionBlock)
		//   - не мутирует Meta["flagged"] (не влияет на downstream)
		//   - не вызывает recordFlag (не влияет на rate-limiter)
		//   - не применяет SanitizedText (не изменяет request/response)
		//   - не участвует в compareAction/compareSeverity итога
		// Append only non-allow: ActionAllow в shadow — шум, нечего
		// сигналить оператору.
		if entry.mode == ModeShadow {
			if d.Action != ActionAllow {
				shadowDecisions = append(shadowDecisions, ShadowDecision{
					Inspector: d.InspectorName,
					Action:    d.Action,
					Reason:    d.Reason,
					Severity:  d.Severity,
				})
			}
			continue
		}

		// ModeEnforce (default): оригинальное поведение pipeline.
		allFindings = append(allFindings, d.Findings...)

		if compareSeverity(d.Severity, highestSeverity) > 0 {
			highestSeverity = d.Severity
		}

		if d.Action == ActionBlock {
			d.Findings = allFindings
			d.ShadowDecisions = shadowDecisions
			return d, nil
		}

		// Cross-inspector signal (PR-3): если enforce-inspector вернул
		// non-allow, помечаем payload.Meta["flagged"]="true" для
		// downstream inspectors. Shadow в этом участия НЕ принимает.
		if d.Action == ActionFlag || d.Action == ActionSanitize {
			if payload.Meta == nil {
				payload.Meta = make(map[string]string)
			}
			payload.Meta["flagged"] = "true"
		}

		if compareAction(d.Action, finalAction) > 0 {
			finalAction = d.Action
			finalReason = d.Reason
			finalInspectorName = d.InspectorName
			finalSanitizedText = d.SanitizedText
		}

		if d.Action == ActionFlag {
			p.recordFlag(payload.UserID)
		}
	}

	return &Decision{
		Action:          finalAction,
		Reason:          finalReason,
		Severity:        highestSeverity,
		Findings:        allFindings,
		InspectorName:   finalInspectorName,
		SanitizedText:   finalSanitizedText,
		ShadowDecisions: shadowDecisions,
	}, nil
}

// recordFlag вызывается только для enforce-инспекторов (см. run()).
// ContentRateLimiter в shadow-режиме сам по себе НЕ исполняется (его
// пропустит entry.mode == ModeDisabled/ModeShadow), так что эта функция
// по-прежнему работает корректно.
func (p *Pipeline) recordFlag(userID string) {
	for _, entry := range p.entries {
		if rl, ok := entry.inspector.(*ContentRateLimiter); ok {
			rl.RecordFlag(userID)
		}
	}
}

// compareAction сравнивает действия по степени серьёзности.
func compareAction(a, b Action) int {
	order := map[Action]int{
		ActionAllow:    0,
		ActionFlag:     1,
		ActionSanitize: 2,
	}
	return order[a] - order[b]
}

func compareSeverity(a, b Severity) int {
	order := map[Severity]int{
		SeverityLow:      0,
		SeverityMedium:   1,
		SeverityHigh:     2,
		SeverityCritical: 3,
	}
	return order[a] - order[b]
}

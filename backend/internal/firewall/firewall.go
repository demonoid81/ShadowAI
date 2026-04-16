package firewall

import "context"

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

type Decision struct {
	Action        Action    `json:"action"`
	Reason        string    `json:"reason"`
	Severity      Severity  `json:"severity"`
	Findings      []Finding `json:"findings"`
	InspectorName string    `json:"inspector_name"`
	// SanitizedText непусто только когда Action == ActionSanitize.
	// Содержит очищенную версию исходного текста.
	SanitizedText string `json:"sanitized_text,omitempty"`
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

type Pipeline struct {
	inspectors []Inspector
}

func NewPipeline() *Pipeline {
	return &Pipeline{}
}

func (p *Pipeline) Register(i Inspector) {
	p.inspectors = append(p.inspectors, i)
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
	highestSeverity := SeverityLow
	finalAction := ActionAllow
	var finalReason string
	var finalInspectorName string
	var finalSanitizedText string

	for _, inspector := range p.inspectors {
		d, err := fn(inspector)(ctx, payload)
		if err != nil {
			return nil, err
		}
		if d == nil {
			continue
		}

		d.InspectorName = inspector.Name()
		allFindings = append(allFindings, d.Findings...)

		if compareSeverity(d.Severity, highestSeverity) > 0 {
			highestSeverity = d.Severity
		}

		if d.Action == ActionBlock {
			d.Findings = allFindings
			return d, nil
		}

		// Track worst non-block action: sanitize > flag > allow
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
		Action:        finalAction,
		Reason:        finalReason,
		Severity:      highestSeverity,
		Findings:      allFindings,
		InspectorName: finalInspectorName,
		SanitizedText: finalSanitizedText,
	}, nil
}

// recordFlag вызывает RecordFlag у ContentRateLimiter, если он зарегистрирован.
func (p *Pipeline) recordFlag(userID string) {
	for _, inspector := range p.inspectors {
		if rl, ok := inspector.(*ContentRateLimiter); ok {
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

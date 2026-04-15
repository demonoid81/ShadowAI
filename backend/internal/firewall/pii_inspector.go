package firewall

import (
	"context"

	"github.com/shadowai/backend/internal/pii"
)

// PIIInspector wraps pii.Scan into the firewall Inspector interface.
// It flags any detected PII with pii:<type> findings.
type PIIInspector struct{}

func NewPIIInspector() *PIIInspector { return &PIIInspector{} }

func (p *PIIInspector) Name() string { return "pii" }

func (p *PIIInspector) InspectRequest(ctx context.Context, payload *Payload) (*Decision, error) {
	return p.inspect(payload.Text), nil
}

func (p *PIIInspector) InspectResponse(ctx context.Context, payload *Payload) (*Decision, error) {
	return p.inspect(payload.Text), nil
}

func (p *PIIInspector) inspect(text string) *Decision {
	findings := pii.Scan(text)
	if len(findings) == 0 {
		return &Decision{Action: ActionAllow}
	}

	fwFindings := make([]Finding, 0, len(findings))
	for _, f := range findings {
		fwFindings = append(fwFindings, Finding{
			Type:     "pii:" + f.Type,
			Severity: SeverityMedium,
			Match:    f.Match,
			Start:    f.Start,
			End:      f.End,
		})
	}

	return &Decision{
		Action:   ActionFlag,
		Reason:   "PII detected",
		Severity: SeverityMedium,
		Findings: fwFindings,
	}
}

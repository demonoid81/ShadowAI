package firewall

import (
	"context"

	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/pii"
)

// DLPInspector wraps dlp.Service into the firewall Inspector interface.
// It maps DLP actions and severities to firewall equivalents.
type DLPInspector struct {
	svc *dlp.Service
}

func NewDLPInspector(svc *dlp.Service) *DLPInspector {
	return &DLPInspector{svc: svc}
}

func (d *DLPInspector) Name() string { return "dlp" }

func (d *DLPInspector) InspectRequest(ctx context.Context, payload *Payload) (*Decision, error) {
	return d.inspect(payload.Text), nil
}

func (d *DLPInspector) InspectResponse(ctx context.Context, payload *Payload) (*Decision, error) {
	return d.inspect(payload.Text), nil
}

func (d *DLPInspector) inspect(text string) *Decision {
	if d.svc == nil {
		return &Decision{Action: ActionAllow}
	}

	piiFindings := pii.Scan(text)
	decision := d.svc.Evaluate(text, piiFindings)

	fwFindings := make([]Finding, 0, len(decision.Findings))
	for _, f := range decision.Findings {
		fwFindings = append(fwFindings, Finding{
			Type:     "dlp:" + f.Type,
			Severity: dlpSeverityToFirewall(f.Severity),
			Match:    f.Match,
			Start:    f.Start,
			End:      f.End,
		})
	}

	var action Action
	switch decision.Action {
	case dlp.DLPActionBlock:
		action = ActionBlock
	case dlp.DLPActionSanitize:
		action = ActionSanitize
	default:
		if len(fwFindings) > 0 {
			action = ActionFlag
		} else {
			action = ActionAllow
		}
	}

	return &Decision{
		Action:   action,
		Reason:   decision.Reason,
		Severity: highestFindingSeverity(fwFindings),
		Findings: fwFindings,
	}
}

// dlpSeverityToFirewall maps dlp.Severity to firewall Severity.
func dlpSeverityToFirewall(s dlp.Severity) Severity {
	switch s {
	case dlp.SeverityHigh:
		return SeverityHigh
	case dlp.SeverityMedium:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// highestFindingSeverity returns the highest severity among findings.
func highestFindingSeverity(findings []Finding) Severity {
	highest := SeverityLow
	for _, f := range findings {
		if compareSeverity(f.Severity, highest) > 0 {
			highest = f.Severity
		}
	}
	return highest
}

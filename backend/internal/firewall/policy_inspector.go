package firewall

import (
	"context"

	"github.com/shadowai/backend/internal/pii"
	"github.com/shadowai/backend/internal/policy"
)

// PolicyInspector wraps policy.Engine into the firewall Inspector interface.
// It only inspects requests; responses always pass through.
type PolicyInspector struct {
	engine *policy.Engine
}

func NewPolicyInspector(engine *policy.Engine) *PolicyInspector {
	return &PolicyInspector{engine: engine}
}

func (p *PolicyInspector) Name() string { return "policy" }

func (p *PolicyInspector) InspectRequest(ctx context.Context, payload *Payload) (*Decision, error) {
	if p.engine == nil {
		return &Decision{Action: ActionAllow}, nil
	}

	piiFindings := pii.Scan(payload.Text)
	evalResult, err := p.engine.Evaluate(ctx, payload.Text, payload.Model, piiFindings)
	if err != nil {
		return nil, err
	}

	switch evalResult.Action {
	case policy.ActionBlocked:
		return &Decision{
			Action:   ActionBlock,
			Reason:   evalResult.Reason,
			Severity: SeverityHigh,
			Findings: []Finding{{
				Type:     "policy:" + evalResult.Rule,
				Severity: SeverityHigh,
				Match:    evalResult.Reason,
			}},
		}, nil
	case policy.ActionWarned:
		return &Decision{
			Action:   ActionFlag,
			Reason:   evalResult.Reason,
			Severity: SeverityMedium,
		}, nil
	default:
		return &Decision{Action: ActionAllow}, nil
	}
}

func (p *PolicyInspector) InspectResponse(ctx context.Context, payload *Payload) (*Decision, error) {
	return &Decision{Action: ActionAllow}, nil
}

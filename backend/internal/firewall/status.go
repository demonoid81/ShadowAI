package firewall

// InspectorStatus represents the runtime status of an inspector.
type InspectorStatus struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Phase   string `json:"phase"` // "request", "response", "both"
}

// Status returns the status of all registered inspectors.
func (p *Pipeline) Status() []InspectorStatus {
	if p == nil {
		return nil
	}
	var statuses []InspectorStatus
	for _, i := range p.inspectors {
		status := InspectorStatus{
			Name:    i.Name(),
			Enabled: true,
			Phase:   "both",
		}
		switch v := i.(type) {
		case *PromptInjectionInspector:
			status.Enabled = v.config.Enabled
			status.Phase = "request"
		case *JailbreakInspector:
			status.Enabled = v.config.Enabled
			status.Phase = "request"
		case *ContentModerationInspector:
			status.Enabled = v.config.Enabled
			status.Phase = "both"
		case *OutputValidationInspector:
			status.Enabled = v.config.Enabled
			status.Phase = "response"
		case *ContentRateLimiter:
			status.Enabled = v.config.Enabled
			status.Phase = "request"
		case *MultiTurnInspector:
			status.Enabled = v.config.Enabled
			status.Phase = "request"
		case *SemanticInspector:
			status.Enabled = v.config.Enabled
			status.Phase = "request"
		case *PIIInspector:
			status.Phase = "both"
		case *DLPInspector:
			status.Phase = "both"
		case *PolicyInspector:
			status.Phase = "request"
		}
		statuses = append(statuses, status)
	}
	return statuses
}

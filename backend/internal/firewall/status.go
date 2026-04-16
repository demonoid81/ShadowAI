package firewall

// InspectorStatus represents the runtime status of an inspector.
type InspectorStatus struct {
	Name      string       `json:"name"`
	Enabled   bool         `json:"enabled"`
	Phase     string       `json:"phase"` // "request", "response", "both"
	JudgeInfo *JudgeStatus `json:"judge,omitempty"`
}

// JudgeStatus — read-only view конфигурации judge в рамках inspector'а.
// APIKey намеренно не экспортируется (см. Judge.Config).
type JudgeStatus struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider,omitempty"`
	Model    string `json:"model,omitempty"`
	// TimeoutSeconds, чтобы оператор мог проверить настройку против
	// наблюдаемого shadowai_judge_latency_seconds distribution.
	TimeoutSeconds float64 `json:"timeout_seconds,omitempty"`
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
			status.JudgeInfo = judgeStatusFor(v.judge)
		case *JailbreakInspector:
			status.Enabled = v.config.Enabled
			status.Phase = "request"
			status.JudgeInfo = judgeStatusFor(v.judge)
		case *ContentModerationInspector:
			status.Enabled = v.config.Enabled
			status.Phase = "both"
			status.JudgeInfo = judgeStatusFor(v.judge)
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

// judgeStatusFor конвертирует Judge в read-only status.
// nil judge → nil result (инспектор работает только на heuristic).
func judgeStatusFor(j *Judge) *JudgeStatus {
	if j == nil {
		return nil
	}
	cfg := j.Config() // sanitized (без APIKey)
	return &JudgeStatus{
		Enabled:        cfg.Enabled,
		Provider:       cfg.Provider,
		Model:          cfg.Model,
		TimeoutSeconds: cfg.Timeout.Seconds(),
	}
}

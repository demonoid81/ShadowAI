package firewall

// InspectorStatus represents the runtime status of an inspector.
type InspectorStatus struct {
	Name      string            `json:"name"`
	Enabled   bool              `json:"enabled"`
	Phase     string            `json:"phase"` // "request", "response", "both"
	JudgeInfo *JudgeStatus      `json:"judge,omitempty"`
	// Mode — runtime-режим инспектора в pipeline (PR-4).
	// "enforce" (по умолчанию), "shadow" или "disabled".
	// Оператор видит его в /proxy/firewall/status и может сопоставить
	// с ожидаемой конфигурацией FIREWALL_MODE_<NAME>.
	Mode string `json:"mode"`
	// SemanticV2 — read-only view конфигурации embedding-based inspector'а
	// (PR-6). Nil для остальных инспекторов. НЕ содержит endpoint/api-key.
	SemanticV2 *SemanticV2Status `json:"semantic_v2,omitempty"`
}

// SemanticV2Status — operational info для semantic_v2 inspector'а.
// Специально исключены: endpoint URL, API key. Оставлены:
// provider/model/thresholds/corpus stats — позволяют оператору
// подтвердить matching client ↔ corpus без раскрытия secrets.
type SemanticV2Status struct {
	Provider       string  `json:"provider,omitempty"`
	Model          string  `json:"model,omitempty"`
	Dimension      int     `json:"dimension,omitempty"`
	Threshold      float64 `json:"threshold,omitempty"`
	BlockThreshold float64 `json:"block_threshold,omitempty"`
	CorpusVersion  int     `json:"corpus_version,omitempty"`
	CorpusItems    int     `json:"corpus_items,omitempty"`
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
	for _, entry := range p.entries {
		status := InspectorStatus{
			Name:    entry.inspector.Name(),
			Enabled: true,
			Phase:   "both",
			Mode:    string(entry.mode),
		}
		switch v := entry.inspector.(type) {
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
		case *SemanticV2Inspector:
			status.Enabled = v.config.Enabled
			status.Phase = "request"
			status.SemanticV2 = semanticV2StatusFor(v)
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

// semanticV2StatusFor собирает безопасный operational view: provider,
// model, thresholds + corpus-статистика. Endpoint и APIKey сюда НЕ
// попадают — utilization через /proxy/firewall/status не должно
// светить secrets (см. тест status_semanticv2_test.go).
func semanticV2StatusFor(s *SemanticV2Inspector) *SemanticV2Status {
	if s == nil {
		return nil
	}
	status := &SemanticV2Status{
		Threshold:      s.config.Threshold,
		BlockThreshold: s.config.BlockThreshold,
	}
	if s.client != nil {
		status.Provider = s.client.Provider()
		status.Model = s.client.Model()
		status.Dimension = s.client.Dimension()
	}
	if s.corpus != nil {
		status.CorpusVersion = s.corpus.Version
		status.CorpusItems = len(s.corpus.Items)
	}
	return status
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

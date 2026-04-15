package firewall

import (
	"context"
	"fmt"
)

// PromptInjectionConfig содержит конфигурацию инспектора prompt injection.
type PromptInjectionConfig struct {
	Enabled            bool    `json:"enabled"`
	HeuristicThreshold float64 `json:"heuristic_threshold"`
	JudgeThreshold     float64 `json:"judge_threshold"`
}

// PromptInjectionInspector обнаруживает попытки prompt injection.
type PromptInjectionInspector struct {
	config   PromptInjectionConfig
	judge    *Judge
	patterns []PatternRule
}

// NewPromptInjectionInspector создаёт новый инспектор prompt injection.
func NewPromptInjectionInspector(cfg PromptInjectionConfig, judge *Judge) *PromptInjectionInspector {
	if cfg.HeuristicThreshold <= 0 {
		cfg.HeuristicThreshold = 0.8
	}
	if cfg.JudgeThreshold <= 0 {
		cfg.JudgeThreshold = 0.4
	}
	return &PromptInjectionInspector{
		config:   cfg,
		judge:    judge,
		patterns: DefaultPromptInjectionPatterns(),
	}
}

// Name возвращает имя инспектора.
func (pi *PromptInjectionInspector) Name() string { return "prompt_injection" }

// InspectRequest проверяет входящий запрос на prompt injection.
func (pi *PromptInjectionInspector) InspectRequest(ctx context.Context, p *Payload) (*Decision, error) {
	if !pi.config.Enabled {
		return &Decision{Action: ActionAllow}, nil
	}

	result := MatchPatterns(p.Text, pi.patterns)
	findings := matchesToFindings(result.Matches, "prompt_injection")

	// Высокий score — блокировка по эвристике
	if result.Score >= pi.config.HeuristicThreshold {
		return &Decision{
			Action:   ActionBlock,
			Reason:   "prompt injection detected (heuristic)",
			Severity: SeverityCritical,
			Findings: findings,
		}, nil
	}

	// Средний score — проверка через LLM judge
	if result.Score >= pi.config.JudgeThreshold {
		if pi.judge != nil {
			judgeResult, err := pi.judge.Evaluate(ctx, p.Text, "prompt_injection")
			if err == nil && judgeResult.IsThreat && judgeResult.Confidence > 0.7 {
				return &Decision{
					Action:   ActionBlock,
					Reason:   "prompt injection detected (LLM judge: " + judgeResult.Reason + ")",
					Severity: SeverityHigh,
					Findings: findings,
				}, nil
			}
		}
		return &Decision{
			Action:   ActionFlag,
			Reason:   "suspicious prompt patterns detected",
			Severity: SeverityMedium,
			Findings: findings,
		}, nil
	}

	return &Decision{Action: ActionAllow, Findings: findings}, nil
}

// InspectResponse не выполняет проверку ответов.
func (pi *PromptInjectionInspector) InspectResponse(ctx context.Context, p *Payload) (*Decision, error) {
	return &Decision{Action: ActionAllow}, nil
}

// matchesToFindings конвертирует совпадения паттернов в findings.
// Используется как prompt_injection, так и jailbreak инспекторами.
func matchesToFindings(matches []PatternMatch, category string) []Finding {
	findings := make([]Finding, 0, len(matches))
	for _, m := range matches {
		findings = append(findings, Finding{
			Type:     category + ":" + m.Rule.Name,
			Severity: SeverityHigh,
			Match:    m.Match,
			Start:    m.Start,
			End:      m.End,
			Meta:     map[string]string{"weight": fmt.Sprintf("%.2f", m.Rule.Weight)},
		})
	}
	return findings
}

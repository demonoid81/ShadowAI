package firewall

import (
	"context"
)

// JailbreakConfig содержит конфигурацию инспектора jailbreak.
type JailbreakConfig struct {
	Enabled            bool    `json:"enabled"`
	HeuristicThreshold float64 `json:"heuristic_threshold"`
	JudgeThreshold     float64 `json:"judge_threshold"`
}

// JailbreakInspector обнаруживает попытки jailbreak.
type JailbreakInspector struct {
	config   JailbreakConfig
	judge    *Judge
	patterns []PatternRule
}

// NewJailbreakInspector создаёт новый инспектор jailbreak.
func NewJailbreakInspector(cfg JailbreakConfig, judge *Judge) *JailbreakInspector {
	if cfg.HeuristicThreshold <= 0 {
		cfg.HeuristicThreshold = 0.8
	}
	if cfg.JudgeThreshold <= 0 {
		cfg.JudgeThreshold = 0.4
	}
	return &JailbreakInspector{
		config:   cfg,
		judge:    judge,
		patterns: DefaultJailbreakPatterns(),
	}
}

// Name возвращает имя инспектора.
func (jb *JailbreakInspector) Name() string { return "jailbreak" }

// InspectRequest проверяет входящий запрос на jailbreak.
func (jb *JailbreakInspector) InspectRequest(ctx context.Context, p *Payload) (*Decision, error) {
	if !jb.config.Enabled {
		return &Decision{Action: ActionAllow}, nil
	}

	result := MatchPatterns(p.Text, jb.patterns)
	findings := matchesToFindings(result.Matches, "jailbreak")

	// Высокий score — блокировка по эвристике
	if result.Score >= jb.config.HeuristicThreshold {
		return &Decision{
			Action:   ActionBlock,
			Reason:   "jailbreak attempt detected (heuristic)",
			Severity: SeverityCritical,
			Findings: findings,
		}, nil
	}

	// Средний score — проверка через LLM judge
	if result.Score >= jb.config.JudgeThreshold {
		if jb.judge != nil {
			judgeResult, err := jb.judge.Evaluate(ctx, p.Text, "jailbreak")
			if err == nil && judgeResult.IsThreat && judgeResult.Confidence > 0.7 {
				return &Decision{
					Action:   ActionBlock,
					Reason:   "jailbreak attempt detected (LLM judge: " + judgeResult.Reason + ")",
					Severity: SeverityHigh,
					Findings: findings,
				}, nil
			}
		}
		return &Decision{
			Action:   ActionFlag,
			Reason:   "suspicious jailbreak patterns detected",
			Severity: SeverityMedium,
			Findings: findings,
		}, nil
	}

	return &Decision{Action: ActionAllow, Findings: findings}, nil
}

// InspectResponse не выполняет проверку ответов.
func (jb *JailbreakInspector) InspectResponse(ctx context.Context, p *Payload) (*Decision, error) {
	return &Decision{Action: ActionAllow}, nil
}

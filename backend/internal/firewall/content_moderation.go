package firewall

import (
	"context"
	"regexp"
)

// ContentModerationConfig содержит конфигурацию инспектора модерации контента.
type ContentModerationConfig struct {
	Enabled            bool    `json:"enabled"`
	HeuristicThreshold float64 `json:"heuristic_threshold"`
	JudgeThreshold     float64 `json:"judge_threshold"`
}

// ContentModerationInspector обнаруживает токсичный, вредоносный или неприемлемый контент.
type ContentModerationInspector struct {
	config   ContentModerationConfig
	judge    *Judge
	patterns []PatternRule
}

// NewContentModerationInspector создаёт новый инспектор модерации контента.
func NewContentModerationInspector(cfg ContentModerationConfig, judge *Judge) *ContentModerationInspector {
	if cfg.HeuristicThreshold <= 0 {
		cfg.HeuristicThreshold = 0.7
	}
	if cfg.JudgeThreshold <= 0 {
		cfg.JudgeThreshold = 0.3
	}
	return &ContentModerationInspector{
		config:   cfg,
		judge:    judge,
		patterns: DefaultContentModerationPatterns(),
	}
}

// Name возвращает имя инспектора.
func (cm *ContentModerationInspector) Name() string { return "content_moderation" }

// InspectRequest проверяет входящий запрос на токсичный контент.
func (cm *ContentModerationInspector) InspectRequest(ctx context.Context, p *Payload) (*Decision, error) {
	return cm.inspect(ctx, p)
}

// InspectResponse проверяет ответ модели на токсичный контент.
func (cm *ContentModerationInspector) InspectResponse(ctx context.Context, p *Payload) (*Decision, error) {
	return cm.inspect(ctx, p)
}

// inspect выполняет общую логику проверки для запросов и ответов.
func (cm *ContentModerationInspector) inspect(ctx context.Context, p *Payload) (*Decision, error) {
	if !cm.config.Enabled {
		return &Decision{Action: ActionAllow}, nil
	}

	result := MatchPatterns(p.Text, cm.patterns)
	findings := matchesToFindings(result.Matches, "content_moderation")

	// Высокий score — блокировка по эвристике
	if result.Score >= cm.config.HeuristicThreshold {
		return &Decision{
			Action:   ActionBlock,
			Reason:   "harmful content detected (heuristic)",
			Severity: SeverityCritical,
			Findings: findings,
		}, nil
	}

	// Средний score — проверка через LLM judge
	if result.Score >= cm.config.JudgeThreshold {
		if cm.judge != nil {
			judgeResult, err := cm.judge.Evaluate(ctx, p.Text, "content_moderation")
			if err == nil && judgeResult.IsThreat && judgeResult.Confidence > 0.7 {
				return &Decision{
					Action:   ActionBlock,
					Reason:   "harmful content detected (LLM judge: " + judgeResult.Reason + ")",
					Severity: SeverityHigh,
					Findings: findings,
				}, nil
			}
		}
		return &Decision{
			Action:   ActionFlag,
			Reason:   "potentially harmful content detected",
			Severity: SeverityMedium,
			Findings: findings,
		}, nil
	}

	return &Decision{Action: ActionAllow, Findings: findings}, nil
}

// DefaultContentModerationPatterns возвращает эвристические паттерны для обнаружения
// токсичного, вредоносного и неприемлемого контента.
func DefaultContentModerationPatterns() []PatternRule {
	return []PatternRule{
		// === Hate speech (0.8-0.9) ===
		{
			Name:    "hate_kill_group",
			Pattern: regexp.MustCompile(`(kill|murder|exterminate|eliminate|eradicate)\s+all\s+(the\s+)?\w+`),
			Weight:  0.9,
			Type:    "hate_speech",
		},
		{
			Name:    "hate_death_to",
			Pattern: regexp.MustCompile(`death\s+to\s+(all\s+)?(the\s+)?\w+`),
			Weight:  0.9,
			Type:    "hate_speech",
		},
		{
			Name:    "hate_group_should_die",
			Pattern: regexp.MustCompile(`\w+\s+should\s+(all\s+)?die`),
			Weight:  0.8,
			Type:    "hate_speech",
		},
		{
			Name:    "hate_genocide_call",
			Pattern: regexp.MustCompile(`\b(ethnic\s+cleansing|racial\s+purge|extermination\s+of)\b`),
			Weight:  0.9,
			Type:    "hate_speech",
		},
		{
			Name:    "hate_genocide_mention",
			Pattern: regexp.MustCompile(`\bgenocide\b`),
			Weight:  0.5,
			Type:    "hate_speech",
		},
		{
			Name:    "hate_holocaust_denial",
			Pattern: regexp.MustCompile(`holocaust\s+(never\s+happened|is\s+a\s+(lie|myth|hoax|fabrication)|didn'?t\s+happen)`),
			Weight:  0.8,
			Type:    "hate_speech",
		},

		// === Violence (0.6-0.8) ===
		{
			Name:    "violence_how_to_make_bomb",
			Pattern: regexp.MustCompile(`how\s+to\s+(make|build|construct|create|assemble)\s+(a\s+)?(bomb|explosive|ied|detonator)`),
			Weight:  0.8,
			Type:    "violence",
		},
		{
			Name:    "violence_how_to_poison",
			Pattern: regexp.MustCompile(`how\s+to\s+(poison|drug|sedate)\s+(a\s+)?(person|someone|people|him|her|them)`),
			Weight:  0.8,
			Type:    "violence",
		},
		{
			Name:    "violence_how_to_kill",
			Pattern: regexp.MustCompile(`how\s+to\s+(kill|murder|assassinate)\s+(a\s+)?(person|someone|people|him|her|them)`),
			Weight:  0.8,
			Type:    "violence",
		},
		{
			Name:    "violence_synthesize",
			Pattern: regexp.MustCompile(`(synthesize|manufacture|produce|cook)\s+(meth|fentanyl|sarin|ricin|anthrax|vx\s+gas|mustard\s+gas|explosives?)`),
			Weight:  0.7,
			Type:    "violence",
		},
		{
			Name:    "violence_build_weapon",
			Pattern: regexp.MustCompile(`(build|make|construct|assemble|3d\s+print)\s+(a\s+)?(weapon|gun|firearm|silencer|suppressor)`),
			Weight:  0.7,
			Type:    "violence",
		},
		{
			Name:    "violence_threats",
			Pattern: regexp.MustCompile(`i\s+(will|am\s+going\s+to|'?m\s+going\s+to|'?m\s+gonna|shall|want\s+to)\s+(hurt|kill|murder|attack|shoot|stab|harm)\b`),
			Weight:  0.6,
			Type:    "violence",
		},

		// === Self-harm (0.7-0.9) ===
		{
			Name:    "selfharm_how_to_end_life",
			Pattern: regexp.MustCompile(`how\s+to\s+(end\s+my\s+life|commit\s+suicide|kill\s+myself)`),
			Weight:  0.9,
			Type:    "self_harm",
		},
		{
			Name:    "selfharm_best_way_to_die",
			Pattern: regexp.MustCompile(`(best|easiest|quickest|most\s+painless)\s+(way|method)\s+to\s+(die|end\s+it|kill\s+(myself|yourself))`),
			Weight:  0.9,
			Type:    "self_harm",
		},
		{
			Name:    "selfharm_encouragement",
			Pattern: regexp.MustCompile(`(you\s+should|just|go\s+ahead\s+and)\s+(kill\s+yourself|end\s+your\s+life|cut\s+yourself|hurt\s+yourself)`),
			Weight:  0.8,
			Type:    "self_harm",
		},
		{
			Name:    "selfharm_methods",
			Pattern: regexp.MustCompile(`(suicide|self[- ]?harm)\s+(method|technique|instruction|guide|tutorial)`),
			Weight:  0.7,
			Type:    "self_harm",
		},

		// === Harassment (0.5-0.7) ===
		{
			Name:    "harassment_doxxing",
			Pattern: regexp.MustCompile(`(find|reveal|expose|leak|post)\s+(their|his|her|someone'?s)\s+(address|phone|identity|personal\s+info|real\s+name|home\s+location)`),
			Weight:  0.7,
			Type:    "harassment",
		},
		{
			Name:    "harassment_stalking",
			Pattern: regexp.MustCompile(`(track|stalk|follow|surveil|spy\s+on)\s+(someone|a\s+person|them|him|her)\s*(home|online|secretly)?`),
			Weight:  0.6,
			Type:    "harassment",
		},
		{
			Name:    "harassment_blackmail",
			Pattern: regexp.MustCompile(`(blackmail|extort|threaten\s+to\s+expose|threaten\s+to\s+release)\b`),
			Weight:  0.5,
			Type:    "harassment",
		},
	}
}

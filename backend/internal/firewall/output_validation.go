package firewall

import (
	"context"
	"regexp"
)

// OutputValidationConfig содержит конфигурацию инспектора валидации выходных данных.
type OutputValidationConfig struct {
	Enabled            bool    `json:"enabled"`
	HeuristicThreshold float64 `json:"heuristic_threshold"`
}

// OutputValidationInspector обнаруживает опасный контент в ответах LLM.
// Работает ТОЛЬКО на ответах — InspectRequest всегда возвращает allow.
type OutputValidationInspector struct {
	config   OutputValidationConfig
	patterns []PatternRule
}

// NewOutputValidationInspector создаёт новый инспектор валидации выходных данных.
func NewOutputValidationInspector(cfg OutputValidationConfig) *OutputValidationInspector {
	if cfg.HeuristicThreshold <= 0 {
		cfg.HeuristicThreshold = 0.7
	}
	return &OutputValidationInspector{
		config:   cfg,
		patterns: DefaultOutputValidationPatterns(),
	}
}

// Name возвращает имя инспектора.
func (ov *OutputValidationInspector) Name() string { return "output_validation" }

// InspectRequest не выполняет проверку запросов — это инспектор только для ответов.
func (ov *OutputValidationInspector) InspectRequest(_ context.Context, _ *Payload) (*Decision, error) {
	return &Decision{Action: ActionAllow}, nil
}

// InspectResponse проверяет ответ LLM на опасный контент.
func (ov *OutputValidationInspector) InspectResponse(_ context.Context, p *Payload) (*Decision, error) {
	if !ov.config.Enabled {
		return &Decision{Action: ActionAllow}, nil
	}

	result := MatchPatterns(p.Text, ov.patterns)
	findings := matchesToFindings(result.Matches, "output_validation")

	if result.Score >= ov.config.HeuristicThreshold {
		return &Decision{
			Action:   ActionBlock,
			Reason:   "dangerous content detected in LLM response",
			Severity: SeverityCritical,
			Findings: findings,
		}, nil
	}

	if result.Score > 0 && result.Score < ov.config.HeuristicThreshold {
		return &Decision{
			Action:   ActionFlag,
			Reason:   "potentially dangerous content detected in LLM response",
			Severity: SeverityMedium,
			Findings: findings,
		}, nil
	}

	return &Decision{Action: ActionAllow, Findings: findings}, nil
}

// DefaultOutputValidationPatterns возвращает паттерны для обнаружения опасного контента в ответах LLM.
func DefaultOutputValidationPatterns() []PatternRule {
	return []PatternRule{
		// === Code injection: shell commands ===
		{
			Name:    "shell_rm_rf",
			Pattern: regexp.MustCompile(`rm\s+-rf\s+/`),
			Weight:  0.9,
			Type:    "code_injection",
		},
		{
			Name:    "shell_sudo",
			Pattern: regexp.MustCompile(`sudo\s+(rm|chmod|chown|mkfs|dd|shutdown|reboot|kill|iptables)`),
			Weight:  0.7,
			Type:    "code_injection",
		},
		{
			Name:    "shell_chmod_777",
			Pattern: regexp.MustCompile(`chmod\s+777\s+`),
			Weight:  0.7,
			Type:    "code_injection",
		},
		{
			Name:    "shell_curl_pipe_bash",
			Pattern: regexp.MustCompile(`curl\s+[^\|]+\|\s*(bash|sh|zsh)`),
			Weight:  0.8,
			Type:    "code_injection",
		},
		{
			Name:    "shell_wget_pipe_sh",
			Pattern: regexp.MustCompile(`wget\s+[^\|]+\|\s*(bash|sh|zsh)`),
			Weight:  0.8,
			Type:    "code_injection",
		},
		// === Code injection: SQL ===
		{
			Name:    "sql_drop_table",
			Pattern: regexp.MustCompile(`drop\s+table\s+`),
			Weight:  0.8,
			Type:    "code_injection",
		},
		{
			Name:    "sql_delete_from",
			Pattern: regexp.MustCompile(`delete\s+from\s+\w+\s*(;|where\s+1\s*=\s*1|--)`),
			Weight:  0.7,
			Type:    "code_injection",
		},
		{
			Name:    "sql_injection_comment",
			Pattern: regexp.MustCompile(`';\s*--`),
			Weight:  0.7,
			Type:    "code_injection",
		},
		{
			Name:    "sql_union_select",
			Pattern: regexp.MustCompile(`union\s+(all\s+)?select\s+`),
			Weight:  0.7,
			Type:    "code_injection",
		},
		// === Code injection: script execution ===
		{
			Name:    "script_eval",
			Pattern: regexp.MustCompile(`\beval\s*\(`),
			Weight:  0.4,
			Type:    "code_injection",
		},
		{
			Name:    "script_exec",
			Pattern: regexp.MustCompile(`\bexec\s*\(`),
			Weight:  0.4,
			Type:    "code_injection",
		},
		{
			Name:    "script_os_system",
			Pattern: regexp.MustCompile(`os\.system\s*\(`),
			Weight:  0.7,
			Type:    "code_injection",
		},
		{
			Name:    "script_subprocess_run",
			Pattern: regexp.MustCompile(`subprocess\.(run|call|popen)\s*\(`),
			Weight:  0.7,
			Type:    "code_injection",
		},
		// === File system manipulation ===
		{
			Name:    "fs_etc_passwd",
			Pattern: regexp.MustCompile(`open\s*\(\s*['"]\/etc\/passwd['"]\s*`),
			Weight:  0.8,
			Type:    "code_injection",
		},
		{
			Name:    "fs_import_os",
			Pattern: regexp.MustCompile(`__import__\s*\(\s*['"]os['"]\s*\)`),
			Weight:  0.8,
			Type:    "code_injection",
		},
		// === Credential exposure ===
		{
			Name:    "credential_password",
			Pattern: regexp.MustCompile(`password\s*=\s*["'][^"']{4,}["']`),
			Weight:  0.9,
			Type:    "credential_exposure",
		},
		// === Data exfiltration ===
		{
			Name:    "exfil_send_to",
			Pattern: regexp.MustCompile(`(send\s+this\s+to|upload\s+to|exfiltrate\s+)`),
			Weight:  0.7,
			Type:    "data_exfiltration",
		},
		// === Harmful instructions ===
		{
			Name:    "harmful_exploit_tools",
			Pattern: regexp.MustCompile(`(use\s+metasploit|run\s+nmap\s+-s)`),
			Weight:  0.8,
			Type:    "harmful_instructions",
		},
	}
}

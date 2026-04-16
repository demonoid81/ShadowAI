package dlp

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/shadowai/backend/internal/pii"
)

type Mode string
type Action string

const (
	DLPModeAudit   Mode = "audit"
	DLPModeEnforce Mode = "enforce"
	DLPModeStrict  Mode = "strict"

	DLPActionAllow    Action = "allowed"
	DLPActionSanitize Action = "sanitized"
	DLPActionBlock    Action = "blocked"
)

type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

type Finding struct {
	Type     string `json:"type"`
	Severity Severity `json:"severity"`
	Match    string `json:"match"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
}

type Decision struct {
	Action   Action    `json:"action"`
	Reason   string    `json:"reason"`
	Findings []Finding `json:"findings"`
}

type Service struct {
	mode Mode
}

func NewService(mode string) *Service {
	return &Service{mode: normalizeMode(mode)}
}

func normalizeMode(mode string) Mode {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case string(DLPModeAudit):
		return DLPModeAudit
	case string(DLPModeStrict):
		return DLPModeStrict
	case string(DLPModeEnforce):
		return DLPModeEnforce
	default:
		return DLPModeEnforce
	}
}

func (s *Service) Evaluate(text string, piiFindings []pii.Finding) Decision {
	findings := s.detectFindings(text, piiFindings)
	return s.makeDecision(text, findings)
}

func (s *Service) Sanitize(text string, piiFindings []pii.Finding) string {
	findings := s.detectFindings(text, piiFindings)
	return sanitizeText(text, findings)
}

func (s *Service) Types(findings []Finding) []string {
	seen := make(map[string]struct{}, len(findings))
	var types []string
	for _, finding := range findings {
		if _, ok := seen[finding.Type]; ok {
			continue
		}
		seen[finding.Type] = struct{}{}
		types = append(types, finding.Type)
	}
	return types
}

func (s *Service) detectFindings(text string, piiFindings []pii.Finding) []Finding {
	var findings []Finding

	for _, pf := range piiFindings {
		if pf.Start < 0 || pf.End <= pf.Start || pf.End > len(text) {
			continue
		}
		findings = append(findings, Finding{
			Type:     pf.Type,
			Severity: piiSeverity(pf.Type),
			Match:    pf.Match,
			Start:    pf.Start,
			End:      pf.End,
		})
	}

	for _, rule := range secretRules() {
		matches := rule.re.FindAllStringIndex(text, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			start, end := m[0], m[1]
			if start < 0 || end <= start || end > len(text) {
				continue
			}
			findings = append(findings, Finding{
				Type:     rule.name,
				Severity: rule.severity,
				Match:    text[start:end],
				Start:    start,
				End:      end,
			})
		}
	}

	return dedupeFindings(findings)
}

func (s *Service) makeDecision(text string, findings []Finding) Decision {
	if s.mode == DLPModeAudit {
		return Decision{Action: DLPActionAllow, Findings: findings}
	}
	if len(findings) == 0 || len(strings.TrimSpace(text)) == 0 {
		return Decision{Action: DLPActionAllow, Findings: findings}
	}

	hasHigh := false
	hasMedium := false
	for _, finding := range findings {
		if finding.Severity == SeverityHigh {
			hasHigh = true
		}
		if finding.Severity == SeverityMedium {
			hasMedium = true
		}
	}
	types := uniqueTypes(findings)

	if hasHigh {
		return Decision{
			Action:   DLPActionBlock,
			Reason:   "high-risk secret leak signals: " + strings.Join(types, ", "),
			Findings: findings,
		}
	}
	if s.mode == DLPModeStrict && hasMedium {
		return Decision{
			Action:   DLPActionBlock,
			Reason:   "strict policy: medium-risk data not allowed: " + strings.Join(types, ", "),
			Findings: findings,
		}
	}
	if hasMedium {
		return Decision{
			Action:   DLPActionSanitize,
			Reason:   "medium-risk sensitive data redacted: " + strings.Join(types, ", "),
			Findings: findings,
		}
	}
	return Decision{
		Action:   DLPActionAllow,
		Findings: findings,
	}
}

func piiSeverity(piitype string) Severity {
	switch piitype {
	case "ssn", "credit_card":
		return SeverityHigh
	case "email", "phone", "ip_address":
		return SeverityMedium
	default:
		return SeverityMedium
	}
}

func dedupeFindings(findings []Finding) []Finding {
	seen := make(map[string]Finding)
	for _, f := range findings {
		key := fmt.Sprintf("%d:%d:%s", f.Start, f.End, f.Type)
		seen[key] = f
	}
	out := make([]Finding, 0, len(seen))
	for _, f := range seen {
		out = append(out, f)
	}
	return out
}

func uniqueTypes(findings []Finding) []string {
	seen := map[string]struct{}{}
	types := make([]string, 0, len(findings))
	for _, f := range findings {
		if _, ok := seen[f.Type]; ok {
			continue
		}
		seen[f.Type] = struct{}{}
		types = append(types, f.Type)
	}
	sort.Strings(types)
	return types
}

func sanitizeText(text string, findings []Finding) string {
	if text == "" || len(findings) == 0 {
		return text
	}
	ordered := dedupeFindings(findings)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Start == ordered[j].Start {
			return ordered[i].End > ordered[j].End
		}
		return ordered[i].Start > ordered[j].Start
	})

	sanitized := text
	for _, f := range ordered {
		if f.Start < 0 || f.End <= f.Start || f.End > len(sanitized) {
			continue
		}
		replacement := "[redacted:" + f.Type + "]"
		sanitized = sanitized[:f.Start] + replacement + sanitized[f.End:]
	}
	return sanitized
}

type precompiledRule struct {
	name     string
	severity Severity
	re       *regexp.Regexp
}

var secretPatterns = []struct {
	name     string
	severity Severity
	expr     string
}{
	{"api_secret", SeverityHigh, `(?i)\b(api[_-]?secret|secret[_-]?key|access[_-]?key)\s*[:=]\s*[A-Za-z0-9._/+]{16,}`},
	{"openai_api_key", SeverityHigh, `\bsk-[A-Za-z0-9]{20,}\b`},
	{"aws_access_key", SeverityHigh, `\bAKIA[0-9A-Z]{16}\b`},
	{"anthropic_api_key", SeverityHigh, `\b(sk-ant-[A-Za-z0-9-_]{10,})`},
	{"github_token", SeverityHigh, `\bgh[pousr]_[A-Za-z0-9]{20,}\b`},
	{"private_key", SeverityHigh, `(?s)-----BEGIN [A-Z ]+PRIVATE KEY-----[A-Za-z0-9+/=\s]*?-----END [A-Z ]+PRIVATE KEY-----`},
	{"bearer_token", SeverityHigh, `(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}\b`},
}

var precompiledSecretPatterns = mustCompileSecretPatterns()

func secretRules() []precompiledRule {
	return precompiledSecretPatterns
}

func mustCompileSecretPatterns() []precompiledRule {
	rules := make([]precompiledRule, 0, len(secretPatterns))
	for _, p := range secretPatterns {
		re := regexp.MustCompile(p.expr)
		rules = append(rules, precompiledRule{
			name:     p.name,
			severity: p.severity,
			re:       re,
		})
	}
	return rules
}

package policy

import (
	"context"
	"strings"

	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/pii"
)

type Action string

const (
	ActionAllowed Action = "allowed"
	ActionBlocked Action = "blocked"
	ActionWarned  Action = "warned"
)

type EvalResult struct {
	Action Action `json:"action"`
	Reason string `json:"reason"`
	Rule   string `json:"rule"`
}

// RuleLister абстрагирует источник правил для тестируемости.
// orgID="" — global (break-glass / default-org) path.
type RuleLister interface {
	List(ctx context.Context, orgID string) ([]domain.PolicyRule, error)
}

type Engine struct {
	repo RuleLister
}

func NewEngine(repo RuleLister) *Engine {
	return &Engine{repo: repo}
}

// policyOrgKey is the context key for per-request org_id used by policy.Engine.
type policyOrgKey struct{}

// WithPolicyOrg injects orgID into context for Engine.Evaluate to use.
func WithPolicyOrg(ctx context.Context, orgID string) context.Context {
	return context.WithValue(ctx, policyOrgKey{}, orgID)
}

func (e *Engine) Evaluate(ctx context.Context, text string, model string, piiFindings []pii.Finding) (*EvalResult, error) {
	orgID, _ := ctx.Value(policyOrgKey{}).(string)
	rules, err := e.repo.List(ctx, orgID)
	if err != nil {
		return nil, err
	}

	piiTypes := pii.DetectedTypes(piiFindings)

	for _, rule := range rules {
		if !rule.IsActive {
			continue
		}
		result := e.evaluateRule(rule, text, model, piiTypes)
		if result != nil {
			return result, nil
		}
	}

	return &EvalResult{Action: ActionAllowed}, nil
}

func (e *Engine) evaluateRule(rule domain.PolicyRule, text string, model string, piiTypes []string) *EvalResult {
	switch rule.RuleType {
	case "pii_block":
		blockedTypes := getStringSlice(rule.Config, "pii_types")
		for _, pt := range piiTypes {
			for _, bt := range blockedTypes {
				if pt == bt {
					return &EvalResult{Action: ActionBlocked, Reason: "PII detected: " + pt, Rule: rule.Name}
				}
			}
		}
	case "pii_warn":
		if len(piiTypes) > 0 {
			return &EvalResult{Action: ActionWarned, Reason: "PII detected: " + strings.Join(piiTypes, ", "), Rule: rule.Name}
		}
	case "keyword_block":
		keywords := getStringSlice(rule.Config, "keywords")
		lower := strings.ToLower(text)
		for _, kw := range keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				return &EvalResult{Action: ActionBlocked, Reason: "Blocked keyword: " + kw, Rule: rule.Name}
			}
		}
	case "model_restrict":
		allowed := getStringSlice(rule.Config, "allowed_models")
		if len(allowed) > 0 {
			for _, am := range allowed {
				if am == model {
					return nil
				}
			}
			return &EvalResult{Action: ActionBlocked, Reason: "Model not allowed: " + model, Rule: rule.Name}
		}
	}
	return nil
}

func getStringSlice(config map[string]any, key string) []string {
	val, ok := config[key]
	if !ok {
		return nil
	}
	slice, ok := val.([]any)
	if !ok {
		return nil
	}
	var result []string
	for _, v := range slice {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// Compiled only under -tags enterprise.

package governance

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// normalizeRoleRules — PR-G2 аналог normalizeRules для role-scoped
// rules: lowercase роли, merge duplicate-role entries (union rules),
// внутри каждого role применяет normalizeRules, сортирует по role
// для детерминизма.
func normalizeRoleRules(in []RoleRule) []RoleRule {
	merged := make(map[string][]ProviderRule)
	order := make([]string, 0, len(in))
	for _, rr := range in {
		role := strings.ToLower(strings.TrimSpace(rr.Role))
		if role == "" {
			continue
		}
		if _, ok := merged[role]; !ok {
			merged[role] = []ProviderRule{}
			order = append(order, role)
		}
		merged[role] = append(merged[role], rr.Rules...)
	}
	sort.Strings(order)
	out := make([]RoleRule, 0, len(order))
	for _, role := range order {
		out = append(out, RoleRule{
			Role:  role,
			Rules: normalizeRules(merged[role]),
		})
	}
	return out
}

// normalizeRules приводит Rules к canonical form:
//   - provider names trim+lowercase, пустые отсекаются;
//   - modeли trim+lowercase, пустые и дубликаты схлопываются;
//   - duplicate provider rules merge'атся в один с union моделей;
//   - итоговый slice отсортирован по provider name для детерминизма.
//
// Вызывается в Service.Upsert перед repo.Upsert — в БД всегда
// canonical form. Защищает от бага, когда admin случайно положит
// openai + OpenAI как две строки, и от direct-SQL импортов.
func normalizeRules(in []ProviderRule) []ProviderRule {
	merged := make(map[string][]string)
	seenPerProvider := make(map[string]map[string]struct{})
	order := make([]string, 0, len(in))
	for _, r := range in {
		p := strings.ToLower(strings.TrimSpace(r.Provider))
		if p == "" {
			continue
		}
		if _, ok := merged[p]; !ok {
			merged[p] = []string{}
			seenPerProvider[p] = map[string]struct{}{}
			order = append(order, p)
		}
		for _, m := range r.Models {
			nm := strings.ToLower(strings.TrimSpace(m))
			if nm == "" {
				continue
			}
			if _, dup := seenPerProvider[p][nm]; dup {
				continue
			}
			seenPerProvider[p][nm] = struct{}{}
			merged[p] = append(merged[p], nm)
		}
	}
	// Sort providers для стабильного порядка (UI не «прыгает»,
	// тесты детерминистичны).
	sort.Strings(order)
	out := make([]ProviderRule, 0, len(order))
	for _, p := range order {
		out = append(out, ProviderRule{Provider: p, Models: merged[p]})
	}
	return out
}

// Repository — источник active policy. В production — PG-backed
// (см. repository.go); в тестах — in-memory mock.
type Repository interface {
	// GetActive возвращает текущую active policy для org.
	// orgID="" обходит фильтр (global / break-glass path).
	// Если ни одной политики не создано, возвращает (nil, nil).
	GetActive(ctx context.Context, orgID string) (*Policy, error)

	// Upsert сохраняет политику для org. actor — UUID admin'а для audit.
	Upsert(ctx context.Context, p *Policy, actor, orgID string) (*Policy, error)
}

// Service инкапсулирует логику Evaluate и доступ к Repository.
// Nil-safe по замыслу: передавать nil Service в proxy — это явный
// deploy-mode «без governance», все Evaluate возвращают Allow.
type Service struct {
	repo Repository
}

// NewService. Если repo=nil, вызовы Evaluate деградируют к
// CodeGovernanceDisabled (так же, как nil Service). Это упрощает
// dev/testing деплои.
func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

// GetActive — прокси к repo для handler'ов (admin CRUD).
func (s *Service) GetActive(ctx context.Context, orgID string) (*Policy, error) {
	if s == nil || s.repo == nil {
		return nil, nil
	}
	return s.repo.GetActive(ctx, orgID)
}

// Upsert — прокси к repo. Валидация Mode + нормализация Rules.
// Нормализация: lowercase provider/model, merge duplicate
// providers, dedupe моделей, стабильный порядок. Это гарантирует
// canonical form в БД и защищает Evaluate от order-зависимости
// duplicate-rules (review finding PR-G1).
//
// PR-G3: для ModeContextScoped — валидирует ContextRules:
//   - non-empty slice required (пустой = deny-all = misconfiguration);
//   - каждое правило должно иметь non-empty Rules;
//   - Sensitivity values должны быть из enum (или empty = any).
//
// Validation errors возвращаются как *ValidationError — handler map'ит в 400.
func (s *Service) Upsert(ctx context.Context, p *Policy, actor, orgID string) (*Policy, error) {
	if s == nil || s.repo == nil {
		return nil, fmt.Errorf("governance: service not configured")
	}
	if !p.Mode.IsValid() {
		return nil, &ValidationError{Msg: fmt.Sprintf("invalid mode %q", p.Mode)}
	}
	if p.Mode == ModeContextScoped {
		if err := validateContextRules(p.ContextRules); err != nil {
			return nil, err
		}
	}
	p.Rules = normalizeRules(p.Rules)
	p.RoleRules = normalizeRoleRules(p.RoleRules)
	p.ContextRules = normalizeContextRules(p.ContextRules)
	return s.repo.Upsert(ctx, p, actor, orgID)
}

// ValidationError — user-facing validation error from Service.Upsert.
// Handler maps this to 400 Bad Request (not 500 Internal Server Error).
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return "governance: " + e.Msg }

// Evaluate — основной entrypoint для proxy. Проверяет, разрешена ли
// комбинация (role, department, sensitivity, provider, model) текущей active policy.
//
// Decision matrix:
//
//	nil Service                      → Allow (governance_disabled)
//	repo err                         → Deny  (policy_read_failure) + err
//	policy == nil                    → Allow (governance_disabled)
//	Mode == disabled                 → Allow (governance_disabled)
//	Mode == allowlist_strict         → role/dept/sensitivity ignored; strict-evaluate Rules
//	Mode == role_based (PR-G2)       → find RoleRule by role
//	Mode == context_scoped (PR-G3)   → find ContextRule by (dept+role+sensitivity)
//
// Сравнение case-insensitive.
func (s *Service) Evaluate(ctx context.Context, orgID, role, department, sensitivity, provider, model string) (Decision, error) {
	if s == nil || s.repo == nil {
		return Decision{Kind: DecisionAllow, Code: CodeGovernanceDisabled, MatchedRuleIndex: -1}, nil
	}
	p, err := s.repo.GetActive(ctx, orgID)
	if err != nil {
		return Decision{
			Kind:             DecisionDeny,
			Code:             CodePolicyReadFailure,
			Reason:           "не удалось прочитать governance-политику — fail-closed",
			MatchedRuleIndex: -1,
		}, err
	}
	if p == nil || p.Mode == ModeDisabled {
		dec := Decision{Kind: DecisionAllow, Code: CodeGovernanceDisabled, MatchedRuleIndex: -1}
		if p != nil {
			dec.PolicyID = p.ID
		}
		return dec, nil
	}
	switch p.Mode {
	case ModeAllowlistStrict:
		dec := evaluateRules(p.Rules, provider, model, p.ID)
		dec.MatchedRuleIndex = -1
		return dec, nil
	case ModeAllowlistRoleBased:
		dec := evaluateRoleRules(p.RoleRules, role, provider, model, p.ID)
		dec.MatchedRuleIndex = -1
		return dec, nil
	case ModeContextScoped:
		return evaluateContextRules(p.ContextRules, role, department, sensitivity, provider, model, p.ID), nil
	}
	// Неизвестный mode — fail-closed (IsValid отсеял бы на Upsert,
	// но direct-SQL мог внести невалидный value).
	return Decision{
		Kind:             DecisionDeny,
		Code:             CodePolicyReadFailure,
		Reason:           fmt.Sprintf("unknown policy mode %q", p.Mode),
		PolicyID:         p.ID,
		MatchedRuleIndex: -1,
	}, nil
}

// evaluateRules — общая логика allowlist-match для плоского списка
// ProviderRule. Используется и в strict, и в role-based (через
// role-specific rules).
func evaluateRules(rules []ProviderRule, provider, model, policyID string) Decision {
	matchedProvider := false
	for _, r := range rules {
		if !strings.EqualFold(r.Provider, provider) {
			continue
		}
		matchedProvider = true
		for _, m := range r.Models {
			if strings.EqualFold(m, model) {
				return Decision{
					Kind:     DecisionAllow,
					Code:     CodeAllowed,
					PolicyID: policyID,
				}
			}
		}
	}
	if matchedProvider {
		return Decision{
			Kind:     DecisionDeny,
			Code:     CodeUnknownModel,
			Reason:   fmt.Sprintf("модель %q не в allowlist провайдера %q", model, provider),
			PolicyID: policyID,
		}
	}
	return Decision{
		Kind:     DecisionDeny,
		Code:     CodeUnknownProvider,
		Reason:   fmt.Sprintf("провайдер %q не в governance-allowlist", provider),
		PolicyID: policyID,
	}
}

// ---------------------------------------------------------------------------
// PR-G3: context_scoped implementation
// ---------------------------------------------------------------------------

// validateContextRules checks that ContextRules are structurally valid for prod.
func validateContextRules(rules []ContextRule) error {
	if len(rules) == 0 {
		return &ValidationError{Msg: "context_scoped mode requires non-empty context_rules (empty = deny-all; configure rules or switch to disabled mode)"}
	}
	for i, cr := range rules {
		if len(cr.Rules) == 0 {
			return &ValidationError{Msg: fmt.Sprintf("context_rules[%d]: rules must be non-empty (empty rules = deny all providers for this context)", i)}
		}
		for _, s := range cr.Sensitivity {
			if !IsValidSensitivity(string(s)) {
				return &ValidationError{Msg: fmt.Sprintf("context_rules[%d]: unknown sensitivity %q (valid: standard|confidential|restricted|unknown)", i, s)}
			}
		}
	}
	return nil
}

// normalizeContextRules normalises ContextRules for canonical storage.
func normalizeContextRules(in []ContextRule) []ContextRule {
	out := make([]ContextRule, 0, len(in))
	for _, cr := range in {
		cr.Department = strings.TrimSpace(cr.Department)
		cr.Role = strings.ToLower(strings.TrimSpace(cr.Role))
		cr.Rules = normalizeRules(cr.Rules)
		// Normalise sensitivity to lowercase.
		for i, s := range cr.Sensitivity {
			cr.Sensitivity[i] = SensitivityLevel(strings.ToLower(string(s)))
		}
		out = append(out, cr)
	}
	return out
}

// evaluateContextRules implements PR-G3 context_scoped evaluation.
// Iterates ContextRules in order (first full match wins).
// Tracks best partial match for informative deny codes:
//   - no dept match → CodeUnknownDepartment
//   - dept+role matched but sensitivity failed → CodeSensitivityDenied
//   - dept matched but role didn't → CodeUnknownContext
//   - full context match → evaluateRules (may return CodeUnknownProvider/Model)
func evaluateContextRules(rules []ContextRule, role, dept, sensitivity, provider, model, policyID string) Decision {
	const (
		bpNone            = 0
		bpDeptMatched     = 1
		bpDeptRoleMatched = 2 // dept+role matched but sensitivity failed
	)
	best := bpNone

	for i, rule := range rules {
		// Department match: "*" or "" = any.
		if rule.Department != "" && rule.Department != "*" &&
			!strings.EqualFold(rule.Department, dept) {
			continue
		}
		if best < bpDeptMatched {
			best = bpDeptMatched
		}

		// Role match: "*" or "" = any.
		if rule.Role != "" && rule.Role != "*" &&
			!strings.EqualFold(rule.Role, role) {
			continue
		}

		// Sensitivity match: empty slice = any.
		if len(rule.Sensitivity) > 0 {
			sensitivityOK := false
			for _, s := range rule.Sensitivity {
				if strings.EqualFold(string(s), sensitivity) {
					sensitivityOK = true
					break
				}
			}
			if !sensitivityOK {
				if best < bpDeptRoleMatched {
					best = bpDeptRoleMatched
				}
				continue
			}
		}

		// Full context match — evaluate provider/model.
		dec := evaluateRules(rule.Rules, provider, model, policyID)
		dec.MatchedRuleIndex = i
		return dec
	}

	// No full match; use best partial for informative error.
	deptDisplay := dept
	if dept == "" {
		deptDisplay = "<empty>"
	}
	switch best {
	case bpNone:
		return Decision{
			Kind:             DecisionDeny,
			Code:             CodeUnknownDepartment,
			Reason:           fmt.Sprintf("department %q not covered by any context rule (context_scoped requires explicit department assignment)", deptDisplay),
			PolicyID:         policyID,
			MatchedRuleIndex: -1,
		}
	case bpDeptMatched:
		return Decision{
			Kind:             DecisionDeny,
			Code:             CodeUnknownContext,
			Reason:           fmt.Sprintf("no context rule covers role=%q department=%q (role not matched by any rule for this department)", role, deptDisplay),
			PolicyID:         policyID,
			MatchedRuleIndex: -1,
		}
	default: // bpDeptRoleMatched — sensitivity failed
		return Decision{
			Kind:             DecisionDeny,
			Code:             CodeSensitivityDenied,
			Reason:           fmt.Sprintf("sensitivity=%q not permitted for department=%q role=%q by any context rule (check FIREWALL_SA_V2_SHADOW_ONLY or X-Data-Sensitivity header)", sensitivity, deptDisplay, role),
			PolicyID:         policyID,
			MatchedRuleIndex: -1,
		}
	}
}

// evaluateRoleRules — PR-G2. Собирает ВСЕ matching RoleRule для
// caller'а (duplicate entries типа admin + Admin могут появиться
// через direct SQL / legacy import — normalizeRoleRules их merge'ит
// на write, но read-side должен быть robust). Затем применяет
// общую evaluateRules к объединённому списку; она уже PR-G1-robust
// к duplicate providers (обходит все matching).
//
// Если role не встречается ни в одной записи — deny-by-default
// с CodeUnknownRole.
func evaluateRoleRules(roleRules []RoleRule, role, provider, model, policyID string) Decision {
	var matched []ProviderRule
	for _, rr := range roleRules {
		if !strings.EqualFold(rr.Role, role) {
			continue
		}
		matched = append(matched, rr.Rules...)
	}
	if matched == nil {
		return Decision{
			Kind:     DecisionDeny,
			Code:     CodeUnknownRole,
			Reason:   fmt.Sprintf("роль %q не в role_based-policy", role),
			PolicyID: policyID,
		}
	}
	return evaluateRules(matched, provider, model, policyID)
}

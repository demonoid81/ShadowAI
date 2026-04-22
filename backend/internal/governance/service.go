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
	// GetActive возвращает текущую active policy. Если ни одной
	// политики не создано, возвращает (nil, nil) — это штатное
	// состояние свежего deploy.
	GetActive(ctx context.Context) (*Policy, error)

	// Upsert сохраняет политику. Для singleton-модели (phase 1)
	// вызов перезаписывает существующую active policy. actor — UUID
	// admin'а для audit (можно пустым строкой для system CLI).
	Upsert(ctx context.Context, p *Policy, actor string) (*Policy, error)
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
// Никаких side-effects здесь не делаем — это чистое чтение.
func (s *Service) GetActive(ctx context.Context) (*Policy, error) {
	if s == nil || s.repo == nil {
		return nil, nil
	}
	return s.repo.GetActive(ctx)
}

// Upsert — прокси к repo. Валидация Mode + нормализация Rules.
// Нормализация: lowercase provider/model, merge duplicate
// providers, dedupe моделей, стабильный порядок. Это гарантирует
// canonical form в БД и защищает Evaluate от order-зависимости
// duplicate-rules (review finding PR-G1).
func (s *Service) Upsert(ctx context.Context, p *Policy, actor string) (*Policy, error) {
	if s == nil || s.repo == nil {
		return nil, fmt.Errorf("governance: service not configured")
	}
	if !p.Mode.IsValid() {
		return nil, fmt.Errorf("governance: invalid mode %q", p.Mode)
	}
	p.Rules = normalizeRules(p.Rules)
	p.RoleRules = normalizeRoleRules(p.RoleRules)
	return s.repo.Upsert(ctx, p, actor)
}

// Evaluate — основной entrypoint для proxy. Проверяет, разрешена ли
// (role, provider, model)-тройка текущей active policy.
//
// Decision matrix:
//
//	nil Service                      → Allow (governance_disabled)
//	repo err                         → Deny  (policy_read_failure) + err
//	policy == nil                    → Allow (governance_disabled)
//	Mode == disabled                 → Allow (governance_disabled)
//	Mode == allowlist_strict         → role ignored; strict-evaluate Rules
//	Mode == role_based (PR-G2)       → find RoleRule by role:
//	   role не в RoleRules            → Deny (unknown_role)
//	   провайдер не в role's rules   → Deny (unknown_provider)
//	   провайдер в, model не         → Deny (unknown_model)
//	   оба match                     → Allow (allowed)
//
// Сравнение case-insensitive (OpenAI vs openai, GPT-4 vs gpt-4,
// admin vs Admin).
func (s *Service) Evaluate(ctx context.Context, role, provider, model string) (Decision, error) {
	if s == nil || s.repo == nil {
		return Decision{Kind: DecisionAllow, Code: CodeGovernanceDisabled}, nil
	}
	p, err := s.repo.GetActive(ctx)
	if err != nil {
		return Decision{
			Kind:   DecisionDeny,
			Code:   CodePolicyReadFailure,
			Reason: "не удалось прочитать governance-политику — fail-closed",
		}, err
	}
	if p == nil || p.Mode == ModeDisabled {
		dec := Decision{Kind: DecisionAllow, Code: CodeGovernanceDisabled}
		if p != nil {
			dec.PolicyID = p.ID
		}
		return dec, nil
	}
	switch p.Mode {
	case ModeAllowlistStrict:
		return evaluateRules(p.Rules, provider, model, p.ID), nil
	case ModeAllowlistRoleBased:
		return evaluateRoleRules(p.RoleRules, role, provider, model, p.ID), nil
	}
	// Неизвестный mode — fail-closed (IsValid отсеял бы на Upsert,
	// но direct-SQL мог внести невалидный value).
	return Decision{
		Kind:     DecisionDeny,
		Code:     CodePolicyReadFailure,
		Reason:   fmt.Sprintf("unknown policy mode %q", p.Mode),
		PolicyID: p.ID,
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

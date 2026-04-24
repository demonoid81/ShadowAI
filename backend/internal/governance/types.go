// Package governance реализует Provider/Model Governance — первую фазу
// enterprise-контроля над LLM-провайдерами: allowlist провайдеров +
// allowlist моделей внутри провайдера + deny-by-default опция +
// policy visibility. PR-G1 (phase 1).
//
// Licensing split (see ENTERPRISE.md):
//
//   - types.go (this file) — Apache License 2.0. Core proxy зависит
//     только от Evaluator interface и Decision-типов.
//   - service.go, repository.go, handler.go, *_test.go — covered by
//     LICENSE.enterprise. Компилируются только с -tags enterprise.
//
// Core-only build передаёт nil Evaluator в proxy; proxy trivially
// возвращает Allow (nil-safe).
//
// Входит в phase 2 (PR-G2):
//   - role_based Mode — per-role allowlist (см. ModeAllowlistRoleBased,
//     Policy.RoleRules, Evaluator.Evaluate(ctx, role, ...)).
//
// НЕ входит в phase 2 (roadmap):
//   - department/user policy matrix (PR-G3);
//   - sensitivity-aware routing (PR-G3);
//   - DPA/compliance inventory UI/reporting (PR-G3);
//   - policy caching для high-traffic deploys (PR-G2.1).
package governance

import (
	"context"
	"time"
)

// Evaluator — core interface, который proxy использует для
// enforcement. Enterprise-реализация (*Service) satisfies его.
// В Core-build передаётся nil — proxy обходит enforcement.
//
// role — auth.Claims.Role; используется при Mode=role_based и context_scoped.
// department — auth.Claims.Department (trusted JWT); используется при context_scoped.
// sensitivity — из X-Data-Sensitivity header, нормализован ExtractGovernanceContext.
//   Отсутствие/неизвестное → "unknown" (fail-restrictive).
// Proxy всегда передаёт все поля, чтобы signature не менялся при смене mode.
type Evaluator interface {
	Evaluate(ctx context.Context, role, department, sensitivity, provider, model string) (Decision, error)
}

// Mode — режим политики.
type Mode string

const (
	// ModeDisabled — governance не применяется. Используется как
	// bootstrap-состояние (свежий deploy) и как «выключатель» без
	// удаления правил. proxy при ModeDisabled всегда получает Allow.
	ModeDisabled Mode = "disabled"

	// ModeAllowlistStrict — разрешены ТОЛЬКО те (provider, model)
	// пары, которые явно перечислены в Rules. Всё остальное — deny.
	// Это и есть deny-by-default, сформулированное как
	// «default = not in allowlist = denied». Role игнорируется.
	ModeAllowlistStrict Mode = "allowlist_strict"

	// ModeAllowlistRoleBased — PR-G2. Allowlist применяется per role.
	// Каждая роль получает свой список разрешённых (provider, model)
	// пар из Policy.RoleRules. Если role caller'а отсутствует в
	// RoleRules — deny с code=unknown_role (deny-by-default).
	ModeAllowlistRoleBased Mode = "role_based"

	// ModeContextScoped — PR-G3. Allowlist применяется по контексту:
	// (department, sensitivity, role) → []ProviderRule.
	// Требует claims.Department (из JWT). Если контекст не покрыт
	// ни одним ContextRule — deny-by-default.
	ModeContextScoped Mode = "context_scoped"
)

// SensitivityLevel — уровень чувствительности данных для context_scoped routing.
// Устанавливается caller'ом через заголовок X-Data-Sensitivity.
// Отсутствующее или неизвестное значение → SensitivityUnknown (fail-restrictive).
type SensitivityLevel string

const (
	SensitivityStandard     SensitivityLevel = "standard"
	SensitivityConfidential SensitivityLevel = "confidential"
	SensitivityRestricted   SensitivityLevel = "restricted"
	// SensitivityUnknown — header не передан или значение не из enum.
	// context_scoped запрещает доступ при unknown если ни одно правило
	// явно не допускает его.
	SensitivityUnknown SensitivityLevel = "unknown"
)

// IsValidSensitivity reports whether s is a known sensitivity level.
func IsValidSensitivity(s string) bool {
	switch SensitivityLevel(s) {
	case SensitivityStandard, SensitivityConfidential, SensitivityRestricted, SensitivityUnknown:
		return true
	}
	return false
}

// ContextRule — одно правило в context_scoped политике.
// Совпадение — all-of: (department AND role AND sensitivity) → ProviderRule.
// Wildcard "*" или пустая строка в Department/Role = match any.
// Пустой slice в Sensitivity = match any sensitivity.
// Пустой Rules с совпавшим контекстом = deny unknown_provider.
type ContextRule struct {
	// Department задаёт фильтр по department из JWT.
	// "*" или "" = любой department (catch-all).
	Department string `json:"department"`
	// Role задаёт фильтр по role из JWT.
	// "*" или "" = любая роль.
	Role string `json:"role,omitempty"`
	// Sensitivity задаёт список допустимых уровней чувствительности.
	// Пустой = любая sensitivity.
	Sensitivity []SensitivityLevel `json:"sensitivity,omitempty"`
	// Rules — разрешённые (provider, model) пары при совпадении контекста.
	Rules []ProviderRule `json:"rules"`
}

// IsValid — проверка входного значения mode перед сохранением в БД.
// Любой unknown mode отвергается (защита от typo / future-tag из UI,
// который этот backend не умеет обрабатывать).
func (m Mode) IsValid() bool {
	switch m {
	case ModeDisabled, ModeAllowlistStrict, ModeAllowlistRoleBased, ModeContextScoped:
		return true
	}
	return false
}

// ProviderRule — разрешение на один провайдер и список его моделей.
// Пустой Models означает «ни одна модель этого провайдера не
// разрешена» (strict-интерпретация): провайдер присутствует в rules,
// но ни одна модель не разрешена → любой запрос на этого провайдера
// получит DecisionDeny (code=unknown_model).
//
// Если провайдера нет в Rules вовсе, получим DecisionDeny
// (code=unknown_provider).
type ProviderRule struct {
	Provider string   `json:"provider"`
	Models   []string `json:"models"`
}

// RoleRule — PR-G2: список ProviderRule для одной роли. Role string
// хранится lowercase (normalizeRoleRules приводит).
type RoleRule struct {
	Role  string         `json:"role"`
	Rules []ProviderRule `json:"rules"`
}

// Policy — активная governance-политика. Singleton-модель:
// ровно одна IsActive=true строка в provider_governance_policies.
//
// Rules используется при Mode=allowlist_strict (PR-G1).
// RoleRules используется при Mode=role_based (PR-G2).
// ContextRules используется при Mode=context_scoped (PR-G3).
// Поля могут сосуществовать — применяется только то, что соответствует Mode.
type Policy struct {
	ID           string
	Name         string
	Mode         Mode
	Rules        []ProviderRule
	RoleRules    []RoleRule
	ContextRules []ContextRule // PR-G3
	UpdatedAt    time.Time
	UpdatedBy    *string
	IsActive     bool
}

// DecisionKind — результат Evaluate: разрешено или запрещено.
type DecisionKind string

const (
	DecisionAllow DecisionKind = "allow"
	DecisionDeny  DecisionKind = "deny"
)

// Коды Decision.Code — стабильны, используются в admin_event_logs и
// в unit-тестах. Менять с осторожностью.
const (
	CodeAllowed            = "allowed"
	CodeGovernanceDisabled = "governance_disabled"
	CodeUnknownProvider    = "unknown_provider"
	CodeUnknownModel       = "unknown_model"
	CodePolicyReadFailure  = "policy_read_failure"
	// CodeUnknownRole — PR-G2: caller.Role отсутствует в Policy.RoleRules
	// при Mode=role_based. Deny-by-default для unspecified roles.
	CodeUnknownRole = "unknown_role"
	// PR-G3 context_scoped codes.
	// CodeUnknownDepartment — department caller'а не покрыт ни одним ContextRule.
	// Включает случай, когда department = "" (не назначен в JWT).
	CodeUnknownDepartment = "unknown_department"
	// CodeSensitivityDenied — department+role совпали с правилом, но sensitivity
	// не разрешена этим правилом. Fail-restrictive: unknown/missing sensitivity → deny.
	CodeSensitivityDenied = "sensitivity_denied"
	// CodeUnknownContext — ни одно правило не покрывает данную комбинацию
	// (dept+role+sensitivity), хотя department был найден.
	CodeUnknownContext = "unknown_context"
)

// Decision — итог проверки (provider, model) против active policy.
// Code — machine-readable, используется admin_event_logs.metadata.
// Reason — human-readable (подходит для 403-response body и логов).
// PolicyID — идентификатор применённой политики (пустой для
// DecisionAllow при ModeDisabled и для policy_read_failure).
// MatchedRuleIndex — PR-G3: индекс совпавшего ContextRule в
// Policy.ContextRules, или -1 если правило не было найдено.
type Decision struct {
	Kind             DecisionKind
	Code             string
	Reason           string
	PolicyID         string
	MatchedRuleIndex int // -1 if not applicable (non-context_scoped) or no match
}

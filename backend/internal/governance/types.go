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
// НЕ входит в v1:
//   - role-based routing (PR-G2);
//   - department/user policy matrix (PR-G2);
//   - sensitivity-aware routing (PR-G2/G3);
//   - DPA/compliance inventory UI/reporting (PR-G3).
package governance

import (
	"context"
	"time"
)

// Evaluator — core interface, который proxy использует для
// enforcement. Enterprise-реализация (*Service) satisfies его.
// В Core-build передаётся nil — proxy обходит enforcement.
//
// role — auth.Claims.Role caller'а. Используется только при
// Mode=role_based (PR-G2); в других modes ignored. Proxy всегда
// передаёт, чтобы signature не менялся при switch mode оператором.
type Evaluator interface {
	Evaluate(ctx context.Context, role, provider, model string) (Decision, error)
}

// Mode — режим политики. Phase 1 поддерживает два значения.
//
// В будущем (G2) появятся:
//   - role_based — allowlist per role;
//   - department_scoped — matrix (user/department × provider/model).
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
)

// IsValid — проверка входного значения mode перед сохранением в БД.
// Любой unknown mode отвергается (защита от typo / future-tag из UI,
// который этот backend не умеет обрабатывать).
func (m Mode) IsValid() bool {
	switch m {
	case ModeDisabled, ModeAllowlistStrict, ModeAllowlistRoleBased:
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
// RoleRules используется при Mode=role_based (PR-G2). Поля могут
// сосуществовать в одной row — применяется только то, что
// соответствует активному Mode.
type Policy struct {
	ID        string
	Name      string
	Mode      Mode
	Rules     []ProviderRule
	RoleRules []RoleRule
	UpdatedAt time.Time
	UpdatedBy *string
	IsActive  bool
}

// DecisionKind — результат Evaluate: разрешено или запрещено.
type DecisionKind string

const (
	DecisionAllow DecisionKind = "allow"
	DecisionDeny  DecisionKind = "deny"
)

// Decision — итог проверки (provider, model) против active policy.
// Code — machine-readable, используется admin_event_logs.metadata.
// Reason — human-readable (подходит для 403-response body и логов).
// PolicyID — идентификатор применённой политики (пустой для
// DecisionAllow при ModeDisabled и для policy_read_failure).
type Decision struct {
	Kind     DecisionKind
	Code     string
	Reason   string
	PolicyID string
}

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
)

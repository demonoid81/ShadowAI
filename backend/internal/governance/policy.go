// Package governance реализует Provider/Model Governance — первую фазу
// enterprise-контроля над LLM-провайдерами: allowlist провайдеров +
// allowlist моделей внутри провайдера + deny-by-default опция +
// policy visibility. PR-G1 (phase 1).
//
// НЕ входит в v1:
//   - role-based routing (PR-G2);
//   - department/user policy matrix (PR-G2);
//   - sensitivity-aware routing (PR-G2/G3);
//   - DPA/compliance inventory UI/reporting (PR-G3).
package governance

import (
	"time"
)

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
	// «default = not in allowlist = denied».
	ModeAllowlistStrict Mode = "allowlist_strict"
)

// IsValid — проверка входного значения mode перед сохранением в БД.
// Любой unknown mode отвергается (защита от typo / future-tag из UI,
// который этот backend не умеет обрабатывать).
func (m Mode) IsValid() bool {
	switch m {
	case ModeDisabled, ModeAllowlistStrict:
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

// Policy — активная governance-политика. В phase 1 система singleton:
// ровно одна IsActive=true строка в provider_governance_policies.
type Policy struct {
	ID        string
	Name      string
	Mode      Mode
	Rules     []ProviderRule
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
	CodeAllowed             = "allowed"
	CodeGovernanceDisabled  = "governance_disabled"
	CodeUnknownProvider     = "unknown_provider"
	CodeUnknownModel        = "unknown_model"
	CodePolicyReadFailure   = "policy_read_failure"
)

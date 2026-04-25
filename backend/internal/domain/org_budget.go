package domain

import "time"

// OrgBudgetPolicyMode controls how an org's aggregate budget cap is enforced.
type OrgBudgetPolicyMode string

const (
	OrgBudgetDisabled OrgBudgetPolicyMode = "disabled" // no cap check
	OrgBudgetObserve  OrgBudgetPolicyMode = "observe"  // record, never block
	OrgBudgetEnforce  OrgBudgetPolicyMode = "enforce"  // block when cap reached
)

// OrgBudgetPolicy is the per-org monthly spend cap configuration.
type OrgBudgetPolicy struct {
	OrgID              string              `json:"org_id"`
	MonthlyLimitCents  int64               `json:"monthly_limit_cents"` // 0 = unlimited
	Mode               OrgBudgetPolicyMode `json:"mode"`
	UpdatedAt          time.Time           `json:"updated_at"`
	UpdatedBy          *string             `json:"updated_by,omitempty"`
}

// OrgBudgetUsage is the current-month accumulated spend for an org.
type OrgBudgetUsage struct {
	OrgID       string    `json:"org_id"`
	PeriodStart time.Time `json:"period_start"`
	SpentCents  int64     `json:"spent_cents"`
}

// OrgBudgetStatus is the combined policy + usage for the current period.
type OrgBudgetStatus struct {
	Policy    OrgBudgetPolicy `json:"policy"`
	Usage     OrgBudgetUsage  `json:"usage"`
	Remaining int64           `json:"remaining_cents"` // negative = over cap
}

// OrgBudgetDecision is the result of a pre-call org budget check.
// Defined in domain so both proxy (core) and orgbudget (enterprise) share the type.
type OrgBudgetDecision struct {
	Allowed   bool
	Mode      OrgBudgetPolicyMode
	Remaining int64  // remaining cents (negative = over cap)
	OrgID     string
}

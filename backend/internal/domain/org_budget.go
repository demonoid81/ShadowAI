package domain

import "time"

// OrgBudgetPolicyMode controls how an org's aggregate budget cap is enforced.
//
// Mode semantics:
//
//	disabled — no enforcement (never blocks), but actual spend IS still collected
//	           via Adjust(0, actual). Use for safe rollout: collect baseline spend
//	           data first, then move to observe or enforce without data gaps.
//	observe  — no enforcement (never blocks). Actual spend collected. Emits
//	           org_budget_exceeded_observe event + metric when projected spend
//	           crosses the cap. Use for visibility before enabling enforcement.
//	enforce  — hard cap: atomically reserves estimated spend before provider call,
//	           blocks when projected spend >= monthly_limit_cents. Refunds on
//	           failure paths. Actual spend adjusted after provider response.
type OrgBudgetPolicyMode string

const (
	// OrgBudgetDisabled: no enforcement; actual spend still collected (see above).
	OrgBudgetDisabled OrgBudgetPolicyMode = "disabled"
	// OrgBudgetObserve: no enforcement; soft-exceeded event + metrics emitted.
	OrgBudgetObserve  OrgBudgetPolicyMode = "observe"
	// OrgBudgetEnforce: hard cap with atomic reserve; blocks at cap.
	OrgBudgetEnforce  OrgBudgetPolicyMode = "enforce"
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

// OrgBudgetDecision is the result of an atomic pre-call org budget check.
// Defined in domain so both proxy (core) and orgbudget (enterprise) share the type.
type OrgBudgetDecision struct {
	Allowed       bool
	Mode          OrgBudgetPolicyMode
	Remaining     int64  // remaining cents after reservation (negative = over cap)
	OrgID         string
	// ReservedCents is the amount atomically added to org_budget_usage by AtomicCheckAndAdd.
	// Pass to Adjust() after the provider call to finalize (or refund if actual=0).
	ReservedCents int64
}

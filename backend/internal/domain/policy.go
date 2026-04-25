package domain

type PolicyRule struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	RuleType string                 `json:"rule_type"`
	Config   map[string]interface{} `json:"config"`
	IsActive bool                   `json:"is_active"`
	Priority int                    `json:"priority"`
	OrgID    string                 `json:"org_id,omitempty"`
}

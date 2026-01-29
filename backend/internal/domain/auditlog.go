package domain

import "time"

type AuditLog struct {
	ID               string    `json:"id"`
	UserID           string    `json:"user_id"`
	RequestBody      string    `json:"request_body,omitempty"`
	ResponseBody     string    `json:"response_body,omitempty"`
	Model            string    `json:"model"`
	Provider         string    `json:"provider"`
	Endpoint         string    `json:"endpoint"`
	StatusCode       int       `json:"status_code"`
	PromptTokens     int       `json:"prompt_tokens"`
	CompletionTokens int       `json:"completion_tokens"`
	TotalTokens      int       `json:"total_tokens"`
	CostUSD          float64   `json:"cost_usd"`
	PIIDetected      bool      `json:"pii_detected"`
	PIITypes         []string  `json:"pii_types"`
	PolicyAction     string    `json:"policy_action"`
	DurationMs       int       `json:"duration_ms"`
	CreatedAt        time.Time `json:"created_at"`
}

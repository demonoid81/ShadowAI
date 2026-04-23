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
	// PolicyAction — policy/security verdict (allowed/blocked/flagged/
	// sanitized). PR-F7.3: больше НЕ перегружается transport/accounting
	// семантикой — compound marker streaming_buffered_fallback:<...>
	// удалён, transport outcome живёт в Outcome, fallback reason — в
	// FallbackReason.
	PolicyAction     string    `json:"policy_action"`
	// ShadowDecisionsJSON — сериализованный JSONB массив решений shadow-
	// инспекторов (PR-4). policy_action НЕ перегружается shadow-смыслом:
	// shadow-наблюдения живут в отдельном поле, чтобы не терять фактический
	// enforce-итог запроса. Пустая строка означает "не было shadow-решений".
	ShadowDecisionsJSON string    `json:"shadow_decisions_json,omitempty"`
	// PR-F7.3: structured streaming audit fields (RFC §11).
	//
	// Outcome — transport-level итог streaming-запроса. Пустое
	// значение = non-streaming или request-side early reject (stream
	// machinery не запускалась). Словарь:
	//   stream_completed, stream_flagged, stream_blocked,
	//   stream_blocked_midflight, stream_buffered_fallback,
	//   stream_transport_error, stream_usage_parse_failed,
	//   stream_budget_exceeded_soft.
	Outcome string `json:"outcome,omitempty"`
	// FallbackReason — почему incremental не был применён.
	// Non-empty только при outcome=stream_buffered_fallback.
	// Значения: judge_inspector, unsupported_provider,
	// unsupported_inspector (reserved).
	FallbackReason string `json:"fallback_reason,omitempty"`
	// UsageSource — откуда взялась accounting truth. F7.3 использует:
	//   final — provider прислал полный usage report;
	//   none  — usage отсутствует (Found=false) или parser вернул err.
	// partial зарезервирован для F7.4 (когда parser'ы научатся
	// сообщать intermediate-state). В F7.3 не эмитится.
	UsageSource string `json:"usage_source,omitempty"`
	DurationMs          int       `json:"duration_ms"`
	CreatedAt           time.Time `json:"created_at"`
}

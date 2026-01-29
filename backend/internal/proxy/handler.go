package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/budget"
	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/pii"
	"github.com/shadowai/backend/internal/policy"
)

var modelPricing = map[string][2]float64{
	"gpt-4o":        {5.0 / 1_000_000, 15.0 / 1_000_000},
	"gpt-4o-mini":   {0.15 / 1_000_000, 0.60 / 1_000_000},
	"gpt-3.5-turbo": {0.50 / 1_000_000, 1.50 / 1_000_000},
}

type Handler struct {
	openAIKey  string
	policySvc  *policy.Service
	auditSvc   *audit.Service
	budgetSvc  *budget.Service
	httpClient *http.Client
}

func NewHandler(openAIKey string, policySvc *policy.Service, auditSvc *audit.Service, budgetSvc *budget.Service) *Handler {
	transport := &OpenAITransport{APIKey: openAIKey}
	return &Handler{
		openAIKey:  openAIKey,
		policySvc:  policySvc,
		auditSvc:   auditSvc,
		budgetSvc:  budgetSvc,
		httpClient: &http.Client{Transport: transport, Timeout: 120 * time.Second},
	}
}

type chatRequest struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

type chatResponse struct {
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

func (h *Handler) ProxyChat(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// 1. Buffer body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	// 2. Parse request
	var chatReq chatRequest
	if err := json.Unmarshal(bodyBytes, &chatReq); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	// Extract all text for PII scanning
	var allText string
	for _, m := range chatReq.Messages {
		allText += m.Content + " "
	}

	// 3. PII Detection
	findings := pii.Scan(allText)
	piiTypes := pii.DetectedTypes(findings)
	piiDetected := len(findings) > 0

	// 4. Policy Evaluation
	evalResult, err := h.policySvc.Engine.Evaluate(r.Context(), allText, chatReq.Model, findings)
	if err != nil {
		http.Error(w, `{"error":"policy error"}`, http.StatusInternalServerError)
		return
	}

	if evalResult.Action == policy.ActionBlocked {
		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: string(bodyBytes), Model: chatReq.Model, Provider: "openai",
			Endpoint: "/v1/chat/completions", StatusCode: 403,
			PIIDetected: piiDetected, PIITypes: piiTypes,
			PolicyAction: "blocked", DurationMs: int(time.Since(start).Milliseconds()),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "blocked by policy", "reason": evalResult.Reason, "rule": evalResult.Rule})
		return
	}

	// 5. Budget Check
	allowed, err := h.budgetSvc.CheckBudget(r.Context(), claims.UserID)
	if err == nil && !allowed {
		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: string(bodyBytes), Model: chatReq.Model, Provider: "openai",
			Endpoint: "/v1/chat/completions", StatusCode: 402,
			PIIDetected: piiDetected, PIITypes: piiTypes,
			PolicyAction: "blocked", DurationMs: int(time.Since(start).Milliseconds()),
		})
		http.Error(w, `{"error":"budget exceeded"}`, http.StatusPaymentRequired)
		return
	}

	// 6. Forward to OpenAI
	proxyReq, err := http.NewRequestWithContext(r.Context(), "POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	proxyReq.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(proxyReq)
	if err != nil {
		http.Error(w, `{"error":"upstream error"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	policyAction := string(evalResult.Action)

	if chatReq.Stream {
		// SSE streaming
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		accumulated, _ := ForwardSSE(w, resp.Body)

		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: string(bodyBytes), ResponseBody: accumulated,
			Model: chatReq.Model, Provider: "openai", Endpoint: "/v1/chat/completions",
			StatusCode: resp.StatusCode, PIIDetected: piiDetected, PIITypes: piiTypes,
			PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})
		return
	}

	// 7. Non-streaming: parse response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, `{"error":"read upstream"}`, http.StatusBadGateway)
		return
	}

	var chatResp chatResponse
	json.Unmarshal(respBody, &chatResp)

	// Calculate cost
	cost := calculateCost(chatReq.Model, chatResp.Usage.PromptTokens, chatResp.Usage.CompletionTokens)

	// 8. Update budget
	if cost > 0 {
		h.budgetSvc.RecordUsage(r.Context(), claims.UserID, cost, chatResp.Usage.TotalTokens)
	}

	// 9. Audit log
	h.auditSvc.Log(&domain.AuditLog{
		ID: uuid.New().String(), UserID: claims.UserID,
		RequestBody: string(bodyBytes), ResponseBody: string(respBody),
		Model: chatReq.Model, Provider: "openai", Endpoint: "/v1/chat/completions",
		StatusCode: resp.StatusCode,
		PromptTokens: chatResp.Usage.PromptTokens, CompletionTokens: chatResp.Usage.CompletionTokens,
		TotalTokens: chatResp.Usage.TotalTokens, CostUSD: cost,
		PIIDetected: piiDetected, PIITypes: piiTypes,
		PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
	})

	// Forward response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func calculateCost(model string, promptTokens, completionTokens int) float64 {
	prices, ok := modelPricing[model]
	if !ok {
		prices = modelPricing["gpt-4o-mini"]
	}
	return float64(promptTokens)*prices[0] + float64(completionTokens)*prices[1]
}

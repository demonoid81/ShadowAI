package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/budget"
	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/pii"
	"github.com/shadowai/backend/internal/policy"
)

// maxBodySize is the maximum allowed request body size (10 MB).
const maxBodySize = 10 << 20

type chatRequest struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

// Handler is the multi-provider proxy handler.
type Handler struct {
	registry   *Registry
	policySvc  *policy.Service
	auditSvc   *audit.Service
	budgetSvc  *budget.Service
	httpClient *http.Client
}

// NewHandler creates a new multi-provider proxy handler.
func NewHandler(registry *Registry, policySvc *policy.Service, auditSvc *audit.Service, budgetSvc *budget.Service) *Handler {
	return &Handler{
		registry:   registry,
		policySvc:  policySvc,
		auditSvc:   auditSvc,
		budgetSvc:  budgetSvc,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
}

// ProxyChat handles requests to /proxy/{provider}/{path:.*}
func (h *Handler) ProxyChat(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// 1. Resolve provider
	vars := mux.Vars(r)
	providerName := vars["provider"]
	provider, ok := h.registry.Get(providerName)
	if !ok {
		http.Error(w, `{"error":"unknown provider"}`, http.StatusBadRequest)
		return
	}

	// 2. Buffer body with size limit
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBodySize)+1))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if len(bodyBytes) > maxBodySize {
		http.Error(w, `{"error":"request body too large"}`, http.StatusRequestEntityTooLarge)
		return
	}

	// 3. Parse request to extract model and messages
	var chatReq chatRequest
	if err := json.Unmarshal(bodyBytes, &chatReq); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	model := chatReq.Model
	if model == "" {
		model = provider.DefaultModel()
	}

	// 3.5. Validate model
	if !isModelSupported(provider, model) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":            "unsupported model",
			"model":            model,
			"supported_models": provider.SupportedModels(),
		})
		return
	}

	// Extract all text for PII scanning
	var allText string
	for _, m := range chatReq.Messages {
		allText += m.Content + " "
	}

	// 4. PII Detection
	findings := pii.Scan(allText)
	piiTypes := pii.DetectedTypes(findings)
	piiDetected := len(findings) > 0

	// 5. Policy Evaluation
	evalResult, err := h.policySvc.Engine.Evaluate(r.Context(), allText, model, findings)
	if err != nil {
		http.Error(w, `{"error":"policy error"}`, http.StatusInternalServerError)
		return
	}

	endpoint := r.URL.Path
	// Strip /proxy/{provider} prefix for audit
	if idx := strings.Index(endpoint, "/"+providerName+"/"); idx >= 0 {
		endpoint = endpoint[idx+len(providerName)+1:]
	}

	if evalResult.Action == policy.ActionBlocked {
		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: string(bodyBytes), Model: model, Provider: providerName,
			Endpoint: endpoint, StatusCode: 403,
			PIIDetected: piiDetected, PIITypes: piiTypes,
			PolicyAction: "blocked", DurationMs: int(time.Since(start).Milliseconds()),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "blocked by policy", "reason": evalResult.Reason, "rule": evalResult.Rule})
		return
	}

	// 6. Budget Check
	allowed, err := h.budgetSvc.CheckBudget(r.Context(), claims.UserID)
	if err == nil && !allowed {
		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: string(bodyBytes), Model: model, Provider: providerName,
			Endpoint: endpoint, StatusCode: 402,
			PIIDetected: piiDetected, PIITypes: piiTypes,
			PolicyAction: "blocked", DurationMs: int(time.Since(start).Milliseconds()),
		})
		http.Error(w, `{"error":"budget exceeded"}`, http.StatusPaymentRequired)
		return
	}

	// 7. Build provider-specific request with retry
	resp, err := doWithRetry(h.httpClient, func() (*http.Request, error) {
		return provider.BuildRequest(r.Context(), bodyBytes, model)
	}, 2)
	if err != nil {
		http.Error(w, `{"error":"upstream error"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	policyAction := string(evalResult.Action)

	// 8. Handle streaming
	if chatReq.Stream {
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		var accumulated string
		switch provider.StreamFormat() {
		case StreamNDJSON:
			accumulated, _ = ForwardNDJSON(w, resp.Body)
		default:
			accumulated, _ = ForwardSSE(w, resp.Body)
		}

		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: string(bodyBytes), ResponseBody: accumulated,
			Model: model, Provider: providerName, Endpoint: endpoint,
			StatusCode: resp.StatusCode, PIIDetected: piiDetected, PIITypes: piiTypes,
			PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})
		return
	}

	// 9. Non-streaming: parse response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, `{"error":"read upstream"}`, http.StatusBadGateway)
		return
	}

	promptTokens, completionTokens, totalTokens, cost, _ := provider.ParseResponse(respBody)

	// 10. Update budget
	if cost > 0 {
		h.budgetSvc.RecordUsage(r.Context(), claims.UserID, cost, totalTokens)
	}

	// 11. Audit log
	h.auditSvc.Log(&domain.AuditLog{
		ID: uuid.New().String(), UserID: claims.UserID,
		RequestBody: string(bodyBytes), ResponseBody: string(respBody),
		Model: model, Provider: providerName, Endpoint: endpoint,
		StatusCode: resp.StatusCode,
		PromptTokens: promptTokens, CompletionTokens: completionTokens,
		TotalTokens: totalTokens, CostUSD: cost,
		PIIDetected: piiDetected, PIITypes: piiTypes,
		PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
	})

	// Forward response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// ListProviders returns JSON with all registered providers and their models.
func (h *Handler) ListProviders(w http.ResponseWriter, r *http.Request) {
	type providerInfo struct {
		Name         string   `json:"name"`
		DefaultModel string   `json:"default_model"`
		Models       []string `json:"supported_models"`
	}

	providers := h.registry.ListProviders()
	result := make([]providerInfo, 0, len(providers))
	for _, p := range providers {
		result = append(result, providerInfo{
			Name:         p.Name(),
			DefaultModel: p.DefaultModel(),
			Models:       p.SupportedModels(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"providers": result,
	})
}

// isModelSupported checks if the model is in the provider's supported models list.
func isModelSupported(provider Provider, model string) bool {
	for _, m := range provider.SupportedModels() {
		if m == model {
			return true
		}
	}
	return false
}

package proxy

import (
	"encoding/json"
	"fmt"
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
	registry      *Registry
	policySvc     *policy.Service
	auditSvc      *audit.Service
	budgetSvc     *budget.Service
	httpClient    *http.Client
	router        *Router
	cache         *SemanticCache
	healthTracker *HealthTracker
}

// NewHandler creates a new multi-provider proxy handler.
func NewHandler(
	registry *Registry,
	policySvc *policy.Service,
	auditSvc *audit.Service,
	budgetSvc *budget.Service,
	router *Router,
	cache *SemanticCache,
	healthTracker *HealthTracker,
) *Handler {
	return &Handler{
		registry:      registry,
		policySvc:     policySvc,
		auditSvc:      auditSvc,
		budgetSvc:     budgetSvc,
		httpClient:    &http.Client{Timeout: 120 * time.Second},
		router:        router,
		cache:         cache,
		healthTracker: healthTracker,
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
	callStart := time.Now()
	resp, err := doWithRetry(h.httpClient, func() (*http.Request, error) {
		return provider.BuildRequest(r.Context(), bodyBytes, model)
	}, 2)
	if err != nil {
		if h.healthTracker != nil {
			h.healthTracker.RecordFailure(r.Context(), providerName)
		}
		http.Error(w, `{"error":"upstream error"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if h.healthTracker != nil {
		latencyMs := time.Since(callStart).Milliseconds()
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			h.healthTracker.RecordSuccess(r.Context(), providerName, latencyMs)
		} else {
			h.healthTracker.RecordFailure(r.Context(), providerName)
		}
	}

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

// UnifiedChat handles POST /proxy/chat — intelligent routing with fallback.
func (h *Handler) UnifiedChat(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// 1. Buffer body
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBodySize)+1))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if len(bodyBytes) > maxBodySize {
		http.Error(w, `{"error":"request body too large"}`, http.StatusRequestEntityTooLarge)
		return
	}

	// 2. Parse request
	var chatReq chatRequest
	if err := json.Unmarshal(bodyBytes, &chatReq); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	model := chatReq.Model
	noCache := r.Header.Get("X-No-Cache") == "true"

	// 3. Cache check (non-streaming only)
	if h.cache != nil && !chatReq.Stream && !noCache {
		messagesJSON, _ := json.Marshal(chatReq.Messages)
		cacheKey := CacheKey("", model, messagesJSON)
		entry, err := h.cache.Get(r.Context(), cacheKey)
		if err == nil && entry != nil {
			h.cache.IncrHit(r.Context())
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Cache", "HIT")
			w.Header().Set("X-Provider", entry.Provider)
			w.WriteHeader(entry.StatusCode)
			w.Write(entry.Body)
			return
		}
		if h.cache != nil {
			h.cache.IncrMiss(r.Context())
		}
	}

	// 4. Extract text for PII scanning
	var allText string
	for _, m := range chatReq.Messages {
		allText += m.Content + " "
	}

	findings := pii.Scan(allText)
	piiTypes := pii.DetectedTypes(findings)
	piiDetected := len(findings) > 0

	// 5. Policy Evaluation
	evalResult, err := h.policySvc.Engine.Evaluate(r.Context(), allText, model, findings)
	if err != nil {
		http.Error(w, `{"error":"policy error"}`, http.StatusInternalServerError)
		return
	}

	if evalResult.Action == policy.ActionBlocked {
		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: string(bodyBytes), Model: model, Provider: "unified",
			Endpoint: "/proxy/chat", StatusCode: 403,
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
		http.Error(w, `{"error":"budget exceeded"}`, http.StatusPaymentRequired)
		return
	}

	// 7. Route — get ordered candidates
	candidates, err := h.router.Route(r.Context(), model)
	if err != nil || len(candidates) == 0 {
		http.Error(w, `{"error":"no providers available"}`, http.StatusServiceUnavailable)
		return
	}

	// 8. Fallback loop
	var lastErr error
	for _, candidate := range candidates {
		provider := candidate.Provider
		providerModel := model
		if providerModel == "" {
			providerModel = provider.DefaultModel()
		}

		callStart := time.Now()
		resp, err := doWithRetry(h.httpClient, func() (*http.Request, error) {
			return provider.BuildRequest(r.Context(), bodyBytes, providerModel)
		}, 1)
		if err != nil {
			if h.healthTracker != nil {
				h.healthTracker.RecordFailure(r.Context(), candidate.Name)
			}
			lastErr = err
			continue
		}

		latencyMs := time.Since(callStart).Milliseconds()

		// Check if upstream returned a retryable error
		if isRetryableStatus(resp.StatusCode) {
			if h.healthTracker != nil {
				h.healthTracker.RecordFailure(r.Context(), candidate.Name)
			}
			resp.Body.Close()
			lastErr = fmt.Errorf("provider %s returned %d", candidate.Name, resp.StatusCode)
			continue
		}

		// Success path
		if h.healthTracker != nil {
			h.healthTracker.RecordSuccess(r.Context(), candidate.Name, latencyMs)
		}

		policyAction := string(evalResult.Action)

		// Streaming
		if chatReq.Stream {
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.Header().Set("X-Provider", candidate.Name)
			w.Header().Set("X-Cache", "MISS")
			w.WriteHeader(resp.StatusCode)

			var accumulated string
			switch provider.StreamFormat() {
			case StreamNDJSON:
				accumulated, _ = ForwardNDJSON(w, resp.Body)
			default:
				accumulated, _ = ForwardSSE(w, resp.Body)
			}
			resp.Body.Close()

			h.auditSvc.Log(&domain.AuditLog{
				ID: uuid.New().String(), UserID: claims.UserID,
				RequestBody: string(bodyBytes), ResponseBody: accumulated,
				Model: providerModel, Provider: candidate.Name, Endpoint: "/proxy/chat",
				StatusCode: resp.StatusCode, PIIDetected: piiDetected, PIITypes: piiTypes,
				PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
			})
			return
		}

		// Non-streaming
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		promptTokens, completionTokens, totalTokens, cost, _ := provider.ParseResponse(respBody)
		if cost > 0 {
			h.budgetSvc.RecordUsage(r.Context(), claims.UserID, cost, totalTokens)
		}

		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: string(bodyBytes), ResponseBody: string(respBody),
			Model: providerModel, Provider: candidate.Name, Endpoint: "/proxy/chat",
			StatusCode: resp.StatusCode,
			PromptTokens: promptTokens, CompletionTokens: completionTokens,
			TotalTokens: totalTokens, CostUSD: cost,
			PIIDetected: piiDetected, PIITypes: piiTypes,
			PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})

		// Cache write
		if h.cache != nil && ShouldCache(resp.StatusCode, chatReq.Stream, noCache) {
			messagesJSON, _ := json.Marshal(chatReq.Messages)
			cacheKey := CacheKey("", providerModel, messagesJSON)
			h.cache.Set(r.Context(), cacheKey, &CacheEntry{
				StatusCode: resp.StatusCode,
				Body:       respBody,
				Provider:   candidate.Name,
				Model:      providerModel,
				CachedAt:   time.Now(),
			})
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Cache", "MISS")
		w.Header().Set("X-Provider", candidate.Name)
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	// All candidates failed
	_ = lastErr
	http.Error(w, `{"error":"all providers failed"}`, http.StatusBadGateway)
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

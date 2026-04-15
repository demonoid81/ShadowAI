package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/budget"
	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/pii"
	"github.com/shadowai/backend/internal/policy"
)

// maxBodySize is the maximum allowed request body size (10 MB).
const maxBodySize = 10 << 20
const (
	maxChatMessages   = 256
	maxMessageLength  = 4000
	maxAuditBodyChars = 4000
)

var allowedRoles = map[string]struct{}{
	"system":    {},
	"user":      {},
	"assistant": {},
	"developer": {},
}

type chatRequest struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	MaxTokens int `json:"max_tokens"`
	MaxCompletionTokens int `json:"max_completion_tokens"`
	MaxTokensToSample int `json:"max_tokens_to_sample"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

type providerTestResponse struct {
	Provider    string `json:"provider"`
	Host        string `json:"host"`
	Port        string `json:"port"`
	Scheme      string `json:"scheme"`
	Reachable   bool   `json:"reachable"`
	LatencyMs   int64  `json:"latency_ms"`
	CheckedAt   time.Time `json:"checked_at"`
	AgeMs       int64     `json:"age_ms"`
	Stale       bool      `json:"stale"`
	EgressBlocked bool `json:"egress_blocked"`
	Message     string `json:"message"`
}

type connectivityCheckRunSummary struct {
	Total           int
	Reachable       int
	Unreachable     int
	EgressBlocked   int
	Stale           int
	NotChecked      int
	Critical        int
	LastError       error
}

// Handler is the multi-provider proxy handler.
type Handler struct {
	registry      *Registry
	policySvc     *policy.Service
	auditSvc      *audit.Service
	budgetSvc     *budget.Service
	dlpSvc        *dlp.Service
	allowedHosts  map[string]struct{}
	httpClient    *http.Client
	router        *Router
	cache         *SemanticCache
	healthTracker *HealthTracker
	maxCompletionTokens int
}

// NewHandler creates a new multi-provider proxy handler.
func NewHandler(
	registry *Registry,
	policySvc *policy.Service,
	auditSvc *audit.Service,
	budgetSvc *budget.Service,
	dlpSvc *dlp.Service,
	allowedProviderHosts string,
	router *Router,
	cache *SemanticCache,
	healthTracker *HealthTracker,
	maxCompletionTokens int,
) *Handler {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &Handler{
		registry:      registry,
		policySvc:     policySvc,
		auditSvc:      auditSvc,
		budgetSvc:     budgetSvc,
		dlpSvc:        dlpSvc,
		allowedHosts:   parseAllowedProviderHosts(allowedProviderHosts),
		httpClient:    &http.Client{Timeout: 120 * time.Second, Transport: transport},
		router:        router,
		cache:         cache,
		healthTracker: healthTracker,
		maxCompletionTokens: maxCompletionTokens,
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
	if err := validateChatRequest(&chatReq); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
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

	endpoint := r.URL.Path
	if idx := strings.Index(endpoint, "/"+providerName+"/"); idx >= 0 {
		endpoint = endpoint[idx+len(providerName)+1:]
	}

	// 4. PII + DLP Detection
	findings := pii.Scan(allText)
	piiTypes := pii.DetectedTypes(findings)
	piiDetected := len(findings) > 0

	requestDecision := dlp.Decision{Action: dlp.DLPActionAllow}
	if h.dlpSvc != nil {
		requestDecision = h.dlpSvc.Evaluate(allText, findings)
	}

	requestPolicyAction := h.mergePolicyAction(string(policy.ActionAllowed), requestDecision.Action)
	requestPIITypes := appendUniqueTypes(piiTypes, h.dlpTypes(requestDecision.Findings))

	if requestDecision.Action == dlp.DLPActionBlock {
		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: h.auditPayload(bodyBytes, findings, requestDecision),
			Model:       model, Provider: providerName,
			Endpoint: endpoint, StatusCode: 403,
			PIIDetected: piiDetected, PIITypes: requestPIITypes,
			PolicyAction: requestPolicyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "blocked by dlp", "reason": requestDecision.Reason})
		return
	}

	requestPayload := bodyBytes
	if requestDecision.Action == dlp.DLPActionSanitize && h.dlpSvc != nil {
		requestPayload = []byte(h.dlpSvc.Sanitize(string(bodyBytes), findings))
	}
	estimatedTokens := estimateTokenCount(allText)
	requestedMaxTokens := requestedCompletionTokens(chatReq)
	maxCompletionTokens, err := h.resolveCompletionTokenLimit(requestedMaxTokens)
	if err != nil {
		http.Error(w, `{"error":"max completion tokens exceeds allowed limit"}`, http.StatusBadRequest)
		return
	}
	estimatedTotalTokens := estimatedTokens + maxCompletionTokens

	// 5. Policy Evaluation
	evalResult, err := h.policySvc.Engine.Evaluate(r.Context(), allText, model, findings)
	if err != nil {
		http.Error(w, `{"error":"policy error"}`, http.StatusInternalServerError)
		return
	}

	policyAction := h.mergePolicyAction(string(evalResult.Action), requestDecision.Action)
	if evalResult.Action == policy.ActionBlocked {
		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: h.auditPayload(bodyBytes, findings, requestDecision),
			Model:       model, Provider: providerName,
			Endpoint: endpoint, StatusCode: 403,
			PIIDetected: piiDetected, PIITypes: requestPIITypes,
			PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "blocked by policy", "reason": evalResult.Reason, "rule": evalResult.Rule})
		return
	}

	// 6. Budget Check
	allowed, err := h.budgetSvc.CheckBudget(r.Context(), claims.UserID, estimatedTotalTokens)
	if err == nil && !allowed {
		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: h.auditPayload(bodyBytes, findings, requestDecision),
			Model:       model, Provider: providerName,
			Endpoint: endpoint, StatusCode: 402,
			PIIDetected: piiDetected, PIITypes: requestPIITypes,
			PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})
		http.Error(w, `{"error":"budget exceeded"}`, http.StatusPaymentRequired)
		return
	}

	// 7. Build provider-specific request with retry
	callStart := time.Now()
	resp, err := doWithRetry(h.httpClient, func() (*http.Request, error) {
		req, err := provider.BuildRequest(r.Context(), requestPayload, model)
		if err != nil {
			return nil, err
		}
		if !h.isAllowedProviderHost(req) {
			return nil, fmt.Errorf("egress blocked for provider host")
		}
		return req, nil
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

	// 8. Handle streaming
	if chatReq.Stream {
		// Collect full stream before releasing downstream output to guarantee DLP enforcement.
		respBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, `{"error":"read upstream"}`, http.StatusBadGateway)
			return
		}

		accumulated := string(respBytes)
		responseFindings := pii.Scan(accumulated)
		responseDecision := dlp.Decision{Action: dlp.DLPActionAllow}
		if h.dlpSvc != nil {
			responseDecision = h.dlpSvc.Evaluate(accumulated, responseFindings)
		}

		responsePolicyAction := h.mergePolicyAction(policyAction, responseDecision.Action)
		responsePIITypes := appendUniqueTypes(piiTypes, pii.DetectedTypes(responseFindings))
		responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(requestDecision.Findings))
		responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(responseDecision.Findings))

		if responseDecision.Action == dlp.DLPActionBlock {
			h.auditSvc.Log(&domain.AuditLog{
				ID: uuid.New().String(), UserID: claims.UserID,
				RequestBody:  h.auditPayload(bodyBytes, findings, requestDecision),
				ResponseBody: h.auditPayload(respBytes, responseFindings, responseDecision),
				Model:        model, Provider: providerName, Endpoint: endpoint,
				StatusCode:   resp.StatusCode,
				PIIDetected:  piiDetected || len(responseFindings) > 0, PIITypes: responsePIITypes,
				PolicyAction: responsePolicyAction, DurationMs: int(time.Since(start).Milliseconds()),
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "blocked by dlp", "reason": responseDecision.Reason})
			return
		}

		responsePayload := respBytes
		if responseDecision.Action == dlp.DLPActionSanitize && h.dlpSvc != nil {
			responsePayload = []byte(h.dlpSvc.Sanitize(accumulated, responseFindings))
		}
		policyAction = responsePolicyAction

		copyHeadersWithoutContentLength(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody:  h.auditPayload(bodyBytes, findings, requestDecision),
			ResponseBody: h.auditPayload(responsePayload, responseFindings, responseDecision),
			Model:        model, Provider: providerName, Endpoint: endpoint,
			StatusCode:   resp.StatusCode,
			PIIDetected:  piiDetected || len(responseFindings) > 0, PIITypes: responsePIITypes,
			PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})
		w.Write(responsePayload)
		return
	}

	// 9. Non-streaming: parse response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, `{"error":"read upstream"}`, http.StatusBadGateway)
		return
	}

	promptTokens, completionTokens, totalTokens, cost, _ := provider.ParseResponse(respBody)
	recordUsage := func() {
		if cost > 0 {
			_ = h.budgetSvc.RecordUsage(r.Context(), claims.UserID, cost, totalTokens)
		}
	}

	// 10. Post-call budget check by cost + tokens
	allowedAfter, err := h.budgetSvc.CheckBudgetAfterUsage(r.Context(), claims.UserID, totalTokens, cost)
	if err == nil && !allowedAfter {
		recordUsage()
		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody:  h.auditPayload(bodyBytes, findings, requestDecision),
			ResponseBody: h.auditPayload(respBody, nil, dlp.Decision{}),
			Model:        model, Provider: providerName, Endpoint: endpoint,
			StatusCode:   http.StatusPaymentRequired,
			PromptTokens: promptTokens, CompletionTokens: completionTokens,
			TotalTokens: totalTokens, CostUSD: cost,
			PIIDetected: piiDetected, PIITypes: piiTypes,
			PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPaymentRequired)
		json.NewEncoder(w).Encode(map[string]string{"error": "budget exceeded"})
		return
	}

	// 11. Response DLP policy + audit
	responseFindings := pii.Scan(string(respBody))
	responseDecision := dlp.Decision{Action: dlp.DLPActionAllow}
	if h.dlpSvc != nil {
		responseDecision = h.dlpSvc.Evaluate(string(respBody), responseFindings)
	}

	responsePolicyAction := h.mergePolicyAction(policyAction, responseDecision.Action)
	responsePIITypes := appendUniqueTypes(piiTypes, pii.DetectedTypes(responseFindings))
	responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(requestDecision.Findings))
	responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(responseDecision.Findings))

	if responseDecision.Action == dlp.DLPActionBlock {
		recordUsage()
		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody:  h.auditPayload(bodyBytes, findings, requestDecision),
			ResponseBody: h.auditPayload(respBody, responseFindings, responseDecision),
			Model:        model, Provider: providerName, Endpoint: endpoint,
			StatusCode:   resp.StatusCode,
			PromptTokens: promptTokens, CompletionTokens: completionTokens,
			TotalTokens: totalTokens, CostUSD: cost,
			PIIDetected: piiDetected || len(responseFindings) > 0, PIITypes: responsePIITypes,
			PolicyAction: responsePolicyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "blocked by dlp", "reason": responseDecision.Reason})
		return
	}

	responsePayload := respBody
	if responseDecision.Action == dlp.DLPActionSanitize && h.dlpSvc != nil {
		responsePayload = []byte(h.dlpSvc.Sanitize(string(respBody), responseFindings))
	}
	policyAction = responsePolicyAction
	recordUsage()

	// 11. Audit log
	h.auditSvc.Log(&domain.AuditLog{
		ID: uuid.New().String(), UserID: claims.UserID,
		RequestBody:  h.auditPayload(bodyBytes, findings, requestDecision),
		ResponseBody: h.auditPayload(responsePayload, responseFindings, responseDecision),
		Model:        model, Provider: providerName, Endpoint: endpoint,
		StatusCode:   resp.StatusCode,
		PromptTokens: promptTokens, CompletionTokens: completionTokens,
		TotalTokens: totalTokens, CostUSD: cost,
		PIIDetected: piiDetected || len(responseFindings) > 0, PIITypes: responsePIITypes,
		PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
	})

	// Forward response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(responsePayload)
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

func (h *Handler) TestAllProviders(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if h.registry == nil {
		http.Error(w, `{"error":"provider registry unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	rawTimeout := strings.TrimSpace(r.URL.Query().Get("timeout_ms"))
	timeout := 5 * time.Second
	if rawTimeout != "" {
		ms, err := strconv.Atoi(rawTimeout)
		if err != nil || ms < 250 || ms > 30000 {
			http.Error(w, `{"error":"invalid timeout_ms"}`, http.StatusBadRequest)
			return
		}
		timeout = time.Duration(ms) * time.Millisecond
	}

	providers := h.registry.ListProviders()
	results := make([]providerTestResponse, 0, len(providers))
	reachableCount := 0
	blockedCount := 0

	for _, provider := range providers {
		sampleModel := provider.DefaultModel()
		response := h.testProviderConnectivity(r.Context(), provider, provider.Name(), sampleModel, timeout)
		h.saveConnectivitySnapshot(r.Context(), response)
		if response.EgressBlocked {
			blockedCount++
		}
		if response.Reachable {
			reachableCount++
		}
		if h.auditSvc != nil {
			responseStatus := http.StatusBadGateway
			policyAction := "blocked"
			if response.EgressBlocked {
				responseStatus = http.StatusForbidden
			}
			if response.Reachable {
				responseStatus = http.StatusOK
				policyAction = "allowed"
			}
			h.auditSvc.Log(&domain.AuditLog{
				ID:           uuid.New().String(),
				UserID:       claims.UserID,
				RequestBody:  `{"provider":"` + provider.Name() + `"}`,
				Model:        sampleModel,
				Provider:     provider.Name(),
				Endpoint:     "/proxy/providers/test",
				StatusCode:   responseStatus,
				PIIDetected:  false,
				PolicyAction: policyAction,
				DurationMs:   int(response.LatencyMs),
			})
		}
		results = append(results, response)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"summary": map[string]interface{}{
			"total":           len(results),
			"reachable":       reachableCount,
			"egress_blocked":  blockedCount,
			"timeout_ms":      timeout.Milliseconds(),
		},
		"results": results,
	})
}

// RunScheduledConnectivityCheck executes network checks for all providers and stores latest results.
// Returns summary without endpoint output.
func (h *Handler) RunScheduledConnectivityCheck(ctx context.Context) connectivityCheckRunSummary {
	summary := connectivityCheckRunSummary{}
	if h == nil || h.healthTracker == nil || h.registry == nil {
		summary.LastError = fmt.Errorf("provider health tracker unavailable")
		return summary
	}

	providers := h.registry.ListProviders()
	summary.Total = len(providers)
	if summary.Total == 0 {
		return summary
	}

	now := time.Now().UTC()
	for _, provider := range providers {
		sampleModel := provider.DefaultModel()
		response := h.testProviderConnectivity(ctx, provider, provider.Name(), sampleModel, 5*time.Second)
		h.saveConnectivitySnapshot(ctx, response)
		resp := response
		if !resp.CheckedAt.IsZero() {
			respAgeMs := now.Sub(resp.CheckedAt).Milliseconds()
			if respAgeMs >= 0 && respAgeMs > int64((5 * time.Minute).Milliseconds()) {
				resp.Stale = true
				summary.Stale++
			}
		}
		if resp.Reachable {
			summary.Reachable++
		} else {
			summary.Unreachable++
			summary.Critical++
		}
		if resp.EgressBlocked {
			summary.EgressBlocked++
			summary.Critical++
		}
		if resp.CheckedAt.IsZero() {
			summary.NotChecked++
		}
	}
	return summary
}

func (h *Handler) testProviderConnectivity(ctx context.Context, provider Provider, providerName, sampleModel string, timeout time.Duration) providerTestResponse {
	start := time.Now()
	response := providerTestResponse{
		Provider: providerName,
		CheckedAt: time.Now().UTC(),
	}

	req, err := provider.BuildRequest(ctx, []byte(`{"model":"`+sampleModel+`","messages":[{"role":"user","content":"proxy connectivity test"}]}`), sampleModel)
	if err != nil {
		response.Message = "unable to build provider request: " + err.Error()
		response.LatencyMs = int64(time.Since(start).Milliseconds())
		return response
	}
	if req == nil || req.URL == nil {
		response.Message = "provider request is invalid"
		response.LatencyMs = int64(time.Since(start).Milliseconds())
		return response
	}

	if !h.isAllowedProviderHost(req) {
		response.Host = req.URL.Hostname()
		response.Port = req.URL.Port()
		response.Scheme = req.URL.Scheme
		response.EgressBlocked = true
		response.LatencyMs = int64(time.Since(start).Milliseconds())
		response.Message = "egress blocked by provider host allowlist"
		return response
	}

	host := req.URL.Hostname()
	if host == "" {
		response.Message = "provider host is empty"
		response.LatencyMs = int64(time.Since(start).Milliseconds())
		return response
	}
	response.Host = host
	response.Scheme = req.URL.Scheme
	response.Port = req.URL.Port()
	if response.Port == "" {
		response.Port = "443"
		if strings.EqualFold(req.URL.Scheme, "http") {
			response.Port = "80"
		}
	}

	addr := net.JoinHostPort(host, response.Port)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: timeout, KeepAlive: 15 * time.Second}).DialContext(cctx, "tcp", addr)
	if err != nil {
		if cctx.Err() == context.DeadlineExceeded {
			response.Message = "connect timeout"
		} else {
			response.Message = err.Error()
		}
		response.LatencyMs = int64(time.Since(start).Milliseconds())
		return response
	}
	_ = conn.Close()

	response.Reachable = true
	response.LatencyMs = int64(time.Since(start).Milliseconds())
	response.Message = "connectivity test passed"
	return response
}

func (h *Handler) TestProvider(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if h.registry == nil {
		http.Error(w, `{"error":"provider registry unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	providerName := strings.ToLower(strings.TrimSpace(mux.Vars(r)["provider"]))
	if providerName == "" {
		http.Error(w, `{"error":"provider is required"}`, http.StatusBadRequest)
		return
	}
	provider, ok := h.registry.Get(providerName)
	if !ok {
		http.Error(w, `{"error":"unknown provider"}`, http.StatusNotFound)
		return
	}

	sampleModel := strings.TrimSpace(r.URL.Query().Get("model"))
	if sampleModel == "" {
		sampleModel = provider.DefaultModel()
	}

	rawTimeout := strings.TrimSpace(r.URL.Query().Get("timeout_ms"))
	timeout := 5 * time.Second
	if rawTimeout != "" {
		ms, err := strconv.Atoi(rawTimeout)
		if err != nil || ms < 250 || ms > 30000 {
			http.Error(w, `{"error":"invalid timeout_ms"}`, http.StatusBadRequest)
			return
		}
		timeout = time.Duration(ms) * time.Millisecond
	}

	response := h.testProviderConnectivity(r.Context(), provider, providerName, sampleModel, timeout)
	h.saveConnectivitySnapshot(r.Context(), response)
	if response.EgressBlocked {
		if h.auditSvc != nil {
			h.auditSvc.Log(&domain.AuditLog{
				ID:           uuid.New().String(),
				UserID:       claims.UserID,
				RequestBody:  `{"provider":"` + providerName + `"}`,
				Model:        sampleModel,
				Provider:     providerName,
				Endpoint:     "/proxy/providers/" + providerName + "/test",
				StatusCode:   http.StatusForbidden,
				PIIDetected:  false,
				PolicyAction: "blocked",
				DurationMs:   int(time.Since(start).Milliseconds()),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(response)
		return
	}
	if response.Reachable {
		if h.auditSvc != nil {
			h.auditSvc.Log(&domain.AuditLog{
				ID:           uuid.New().String(),
				UserID:       claims.UserID,
				RequestBody:  `{"provider":"` + providerName + `"}`,
				Model:        sampleModel,
				Provider:     providerName,
				Endpoint:     "/proxy/providers/" + providerName + "/test",
				StatusCode:   http.StatusOK,
				PIIDetected:  false,
				PolicyAction: "allowed",
				DurationMs:   int(time.Since(start).Milliseconds()),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
		return
	}
	if h.auditSvc != nil {
		h.auditSvc.Log(&domain.AuditLog{
			ID:           uuid.New().String(),
			UserID:       claims.UserID,
			RequestBody:  `{"provider":"` + providerName + `"}`,
			Model:        sampleModel,
			Provider:     providerName,
			Endpoint:     "/proxy/providers/" + providerName + "/test",
			StatusCode:   http.StatusBadGateway,
			PIIDetected:  false,
			PolicyAction: "blocked",
			DurationMs:   int(time.Since(start).Milliseconds()),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	_ = json.NewEncoder(w).Encode(response)
}

// Connectivity checks endpoint (admin) returns latest connectivity snapshot for each provider.
func (h *Handler) ProviderConnectivity(w http.ResponseWriter, r *http.Request) {
	h.providerConnectivity(w, r, false)
}

func (h *Handler) ProviderConnectivityAlerts(w http.ResponseWriter, r *http.Request) {
	h.providerConnectivity(w, r, true)
}

func (h *Handler) providerConnectivity(w http.ResponseWriter, r *http.Request, onlyAlerts bool) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if h.healthTracker == nil || h.registry == nil {
		http.Error(w, `{"error":"provider health tracker unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	rawFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	if onlyAlerts {
		rawFilter = "alerts"
	}
	rawStaleAfter := strings.TrimSpace(r.URL.Query().Get("stale_after_seconds"))
	staleAfter := 10 * time.Minute
	if rawStaleAfter != "" {
		seconds, err := strconv.Atoi(rawStaleAfter)
		if err != nil || seconds < 1 {
			http.Error(w, `{"error":"invalid stale_after_seconds"}`, http.StatusBadRequest)
			return
		}
		staleAfter = time.Duration(seconds) * time.Second
	}

	providers := h.registry.ListProviders()
	results := make([]providerTestResponse, 0, len(providers))
	reachableCount := 0
	blockedCount := 0
	uncheckedCount := 0
	staleCount := 0
	filteredOutCount := 0
	now := time.Now().UTC()

	matchesFilter := func(resp providerTestResponse) bool {
		switch rawFilter {
		case "", "all":
			return true
		case "alerts", "problem", "issues":
			return !resp.Reachable || resp.EgressBlocked || resp.Stale
		case "unreachable":
			return !resp.Reachable
		case "egress":
			return resp.EgressBlocked
		case "stale":
			return resp.Stale
		default:
			return true
		}
	}

	for _, provider := range providers {
		check := h.healthTracker.GetConnectivityCheck(r.Context(), provider.Name())
		if check == nil {
			uncheckedCount++
			resp := providerTestResponse{
				Provider:      provider.Name(),
				Message:       "not checked yet",
				CheckedAt:     time.Time{},
				AgeMs:         -1,
				Stale:         true,
			}
			if matchesFilter(resp) {
				results = append(results, resp)
			} else {
				filteredOutCount++
			}
			continue
		}

		resp := providerTestResponse{
			Provider:      check.Provider,
			Host:          check.Host,
			Port:          check.Port,
			Scheme:        check.Scheme,
			Reachable:     check.Reachable,
			LatencyMs:     check.LatencyMs,
			EgressBlocked: check.EgressBlocked,
			Message:       check.Message,
			CheckedAt:     check.CheckedAt,
		}
		if !check.CheckedAt.IsZero() {
			ageMs := int64(now.Sub(check.CheckedAt).Milliseconds())
			if ageMs < 0 {
				ageMs = 0
			}
			resp.AgeMs = ageMs
			if check.CheckedAt.Add(staleAfter).Before(now) {
				resp.Stale = true
			}
		}
		if resp.Reachable {
			reachableCount++
		}
		if resp.EgressBlocked {
			blockedCount++
		}
		if resp.Stale {
			staleCount++
		}
		if matchesFilter(resp) {
			results = append(results, resp)
		} else {
			filteredOutCount++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"summary": map[string]interface{}{
			"total":             len(providers),
			"visible":           len(results),
			"filtered_out":      filteredOutCount,
			"reachable":         reachableCount,
			"egress_blocked":    blockedCount,
			"not_checked":       uncheckedCount,
			"stale":             staleCount,
			"status_filter":      rawFilter,
			"stale_after_seconds": int(staleAfter.Seconds()),
		},
		"results": results,
	})
}

func (h *Handler) saveConnectivitySnapshot(ctx context.Context, response providerTestResponse) {
	if h == nil || h.healthTracker == nil {
		return
	}
	checkedAt := response.CheckedAt
	if checkedAt.IsZero() {
		checkedAt = time.Now().UTC()
	}
	h.healthTracker.RecordConnectivityCheck(ctx, &ProviderConnectivityCheck{
		Provider:      response.Provider,
		Host:          response.Host,
		Port:          response.Port,
		Scheme:        response.Scheme,
		Reachable:     response.Reachable,
	LatencyMs:     response.LatencyMs,
		EgressBlocked: response.EgressBlocked,
		Message:       response.Message,
		CheckedAt:     checkedAt,
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
	if err := validateChatRequest(&chatReq); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	model := chatReq.Model
	noCache := r.Header.Get("X-No-Cache") == "true"
	var cachePayload []byte
	if h.cache != nil && !chatReq.Stream && !noCache {
		cachePayload = bodyBytes
	}

	// 4. Extract text for PII scanning
	var allText string
	for _, m := range chatReq.Messages {
		allText += m.Content + " "
	}

	findings := pii.Scan(allText)
	piiTypes := pii.DetectedTypes(findings)
	piiDetected := len(findings) > 0

	requestDecision := dlp.Decision{Action: dlp.DLPActionAllow}
	if h.dlpSvc != nil {
		requestDecision = h.dlpSvc.Evaluate(allText, findings)
	}

	requestPolicyAction := h.mergePolicyAction(string(policy.ActionAllowed), requestDecision.Action)
	requestPayload := bodyBytes
	if requestDecision.Action == dlp.DLPActionSanitize && h.dlpSvc != nil {
		requestPayload = []byte(h.dlpSvc.Sanitize(string(bodyBytes), findings))
	}
	estimatedTokens := estimateTokenCount(allText)
	requestedMaxTokens := requestedCompletionTokens(chatReq)
	maxCompletionTokens, err := h.resolveCompletionTokenLimit(requestedMaxTokens)
	if err != nil {
		http.Error(w, `{"error":"max completion tokens exceeds allowed limit"}`, http.StatusBadRequest)
		return
	}
	estimatedTotalTokens := estimatedTokens + maxCompletionTokens
	requestPIITypes := appendUniqueTypes(piiTypes, h.dlpTypes(requestDecision.Findings))

	if requestDecision.Action == dlp.DLPActionBlock {
		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: h.auditPayload(bodyBytes, findings, requestDecision),
			Model:       model, Provider: "unified", Endpoint: "/proxy/chat",
			StatusCode: 403, PIIDetected: piiDetected, PIITypes: requestPIITypes,
			PolicyAction: requestPolicyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "blocked by dlp", "reason": requestDecision.Reason})
		return
	}

	// 5. Policy Evaluation
	evalResult, err := h.policySvc.Engine.Evaluate(r.Context(), allText, model, findings)
	if err != nil {
		http.Error(w, `{"error":"policy error"}`, http.StatusInternalServerError)
		return
	}

	policyAction := h.mergePolicyAction(string(evalResult.Action), requestDecision.Action)
	if evalResult.Action == policy.ActionBlocked {
		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: h.auditPayload(bodyBytes, findings, requestDecision),
			Model:       model, Provider: "unified", Endpoint: "/proxy/chat",
			StatusCode: 403, PIIDetected: piiDetected, PIITypes: requestPIITypes,
			PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "blocked by policy", "reason": evalResult.Reason, "rule": evalResult.Rule})
		return
	}

	// 6. Budget Check (estimated: prompt + planned completion)
	allowed, err := h.budgetSvc.CheckBudget(r.Context(), claims.UserID, estimatedTotalTokens)
	if err == nil && !allowed {
		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: h.auditPayload(bodyBytes, findings, requestDecision),
			Model:       model, Provider: "unified", Endpoint: "/proxy/chat",
			StatusCode: 402, PIIDetected: piiDetected, PIITypes: requestPIITypes,
			PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})
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
	cacheChecked := false
	cacheMiss := false
	var lastErr error
	for _, candidate := range candidates {
		provider := candidate.Provider
		providerModel := model
		if providerModel == "" {
			providerModel = provider.DefaultModel()
		}

		// 3. Cache check per provider (non-streaming only)
		if h.cache != nil && !chatReq.Stream && !noCache {
			cacheChecked = true
			cacheKey := CacheKeyForUser(claims.UserID, candidate.Name, providerModel, cachePayload)
			entry, err := h.cache.Get(r.Context(), cacheKey)
			if err == nil && entry != nil {
				h.cache.IncrHit(r.Context())
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Cache", "HIT")
				w.Header().Set("X-Provider", candidate.Name)
				w.WriteHeader(entry.StatusCode)
				w.Write(entry.Body)
				return
			}
			if err == nil {
				cacheMiss = true
			}
		}

		callStart := time.Now()
		resp, err := doWithRetry(h.httpClient, func() (*http.Request, error) {
			req, err := provider.BuildRequest(r.Context(), requestPayload, providerModel)
			if err != nil {
				return nil, err
			}
			if !h.isAllowedProviderHost(req) {
				return nil, fmt.Errorf("egress blocked for provider host")
			}
			return req, nil
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

		// Streaming
		if chatReq.Stream {
			respBytes, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				lastErr = err
				continue
			}

			accumulated := string(respBytes)
			responseFindings := pii.Scan(accumulated)
			responseDecision := dlp.Decision{Action: dlp.DLPActionAllow}
			if h.dlpSvc != nil {
				responseDecision = h.dlpSvc.Evaluate(accumulated, responseFindings)
			}
			responsePolicyAction := h.mergePolicyAction(policyAction, responseDecision.Action)
			responsePIITypes := appendUniqueTypes(piiTypes, pii.DetectedTypes(responseFindings))
			responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(requestDecision.Findings))
			responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(responseDecision.Findings))

			if responseDecision.Action == dlp.DLPActionBlock {
				h.auditSvc.Log(&domain.AuditLog{
					ID: uuid.New().String(), UserID: claims.UserID,
					RequestBody: h.auditPayload(requestPayload, findings, requestDecision), ResponseBody: h.auditPayload(respBytes, responseFindings, responseDecision),
					Model: providerModel, Provider: candidate.Name, Endpoint: "/proxy/chat",
					StatusCode:   resp.StatusCode,
					PromptTokens: 0, CompletionTokens: 0,
					TotalTokens:  0, CostUSD: 0,
					PIIDetected:  piiDetected || len(responseFindings) > 0, PIITypes: responsePIITypes,
					PolicyAction: responsePolicyAction, DurationMs: int(time.Since(start).Milliseconds()),
				})
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "blocked by dlp", "reason": responseDecision.Reason})
				return
			}

			responsePayload := respBytes
			if responseDecision.Action == dlp.DLPActionSanitize && h.dlpSvc != nil {
				responsePayload = []byte(h.dlpSvc.Sanitize(accumulated, responseFindings))
			}
			policyAction = responsePolicyAction

			h.auditSvc.Log(&domain.AuditLog{
				ID: uuid.New().String(), UserID: claims.UserID,
				RequestBody: h.auditPayload(requestPayload, findings, requestDecision), ResponseBody: h.auditPayload(responsePayload, responseFindings, responseDecision),
				Model: providerModel, Provider: candidate.Name, Endpoint: "/proxy/chat",
				StatusCode:   resp.StatusCode,
				PIIDetected:  piiDetected || len(responseFindings) > 0, PIITypes: responsePIITypes,
				PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
			})
			copyHeadersWithoutContentLength(w.Header(), resp.Header)
			w.Header().Set("X-Provider", candidate.Name)
			w.Header().Set("X-Cache", "MISS")
			w.WriteHeader(resp.StatusCode)
			w.Write(responsePayload)
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
		recordUsage := func() {
			if cost > 0 {
				_ = h.budgetSvc.RecordUsage(r.Context(), claims.UserID, cost, totalTokens)
			}
		}

		allowedAfter, err := h.budgetSvc.CheckBudgetAfterUsage(r.Context(), claims.UserID, totalTokens, cost)
		if err == nil && !allowedAfter {
			recordUsage()
			h.auditSvc.Log(&domain.AuditLog{
				ID: uuid.New().String(), UserID: claims.UserID,
				RequestBody:  h.auditPayload(requestPayload, findings, requestDecision),
				ResponseBody: h.auditPayload(respBody, nil, dlp.Decision{}),
				Model:        providerModel, Provider: candidate.Name, Endpoint: "/proxy/chat",
				StatusCode:   http.StatusPaymentRequired,
				PromptTokens: promptTokens, CompletionTokens: completionTokens,
				TotalTokens: totalTokens, CostUSD: cost,
				PIIDetected: piiDetected, PIITypes: piiTypes,
				PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			json.NewEncoder(w).Encode(map[string]string{"error": "budget exceeded"})
			return
		}

		responseFindings := pii.Scan(string(respBody))
		responseDecision := dlp.Decision{Action: dlp.DLPActionAllow}
		if h.dlpSvc != nil {
			responseDecision = h.dlpSvc.Evaluate(string(respBody), responseFindings)
		}
		responsePolicyAction := h.mergePolicyAction(policyAction, responseDecision.Action)
		responsePIITypes := appendUniqueTypes(piiTypes, pii.DetectedTypes(responseFindings))
		responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(requestDecision.Findings))
		responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(responseDecision.Findings))

		if responseDecision.Action == dlp.DLPActionBlock {
			recordUsage()
			h.auditSvc.Log(&domain.AuditLog{
				ID: uuid.New().String(), UserID: claims.UserID,
				RequestBody: h.auditPayload(requestPayload, findings, requestDecision), ResponseBody: h.auditPayload(respBody, responseFindings, responseDecision),
				Model: providerModel, Provider: candidate.Name, Endpoint: "/proxy/chat",
				StatusCode:   resp.StatusCode,
				PromptTokens: promptTokens, CompletionTokens: completionTokens,
				TotalTokens: totalTokens, CostUSD: cost,
				PIIDetected: piiDetected || len(responseFindings) > 0, PIITypes: responsePIITypes,
				PolicyAction: responsePolicyAction, DurationMs: int(time.Since(start).Milliseconds()),
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "blocked by dlp", "reason": responseDecision.Reason})
			return
		}

		responsePayload := respBody
		if responseDecision.Action == dlp.DLPActionSanitize && h.dlpSvc != nil {
			responsePayload = []byte(h.dlpSvc.Sanitize(string(respBody), responseFindings))
		}
		policyAction = responsePolicyAction
		recordUsage()

		h.auditSvc.Log(&domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: h.auditPayload(requestPayload, findings, requestDecision), ResponseBody: h.auditPayload(responsePayload, responseFindings, responseDecision),
			Model: providerModel, Provider: candidate.Name, Endpoint: "/proxy/chat",
			StatusCode:   resp.StatusCode,
			PromptTokens: promptTokens, CompletionTokens: completionTokens,
			TotalTokens: totalTokens, CostUSD: cost,
			PIIDetected: piiDetected || len(responseFindings) > 0, PIITypes: responsePIITypes,
			PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})

		// Cache write
		if h.cache != nil && ShouldCache(resp.StatusCode, chatReq.Stream, noCache) {
			cacheKey := CacheKeyForUser(claims.UserID, candidate.Name, providerModel, cachePayload)
			h.cache.Set(r.Context(), cacheKey, &CacheEntry{
				StatusCode: resp.StatusCode,
				Body:       responsePayload,
				Provider:   candidate.Name,
				Model:      providerModel,
				CachedAt:   time.Now(),
			})
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Cache", "MISS")
		w.Header().Set("X-Provider", candidate.Name)
		w.WriteHeader(resp.StatusCode)
		w.Write(responsePayload)
		return
	}

	if cacheChecked && cacheMiss {
		h.cache.IncrMiss(r.Context())
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

func validateChatRequest(req *chatRequest) error {
	if len(req.Messages) == 0 {
		return fmt.Errorf("messages are required")
	}
	if len(req.Messages) > maxChatMessages {
		return fmt.Errorf("too many messages")
	}

	for _, m := range req.Messages {
		if strings.TrimSpace(m.Role) == "" {
			return fmt.Errorf("message role is required")
		}
		if _, ok := allowedRoles[m.Role]; !ok {
			return fmt.Errorf("unsupported role: %s", m.Role)
		}
		if len(m.Content) > maxMessageLength {
			return fmt.Errorf("message content is too long")
		}
		if m.Role == "system" && strings.TrimSpace(m.Content) == "" {
			return fmt.Errorf("system message content is required")
		}
	}
	return nil
}

func sanitizePayload(payload []byte) string {
	sanitized := string(payload)
	for _, p := range pii.Patterns {
		sanitized = p.Pattern.ReplaceAllString(sanitized, "[redacted:"+p.Name+"]")
	}
	if len(sanitized) > maxAuditBodyChars {
		return sanitized[:maxAuditBodyChars] + "..."
	}
	return sanitized
}

func parseAllowedProviderHosts(raw string) map[string]struct{} {
	parts := strings.Split(raw, ",")
	hosts := make(map[string]struct{}, len(parts))
	for _, host := range parts {
		h := normalizeHostForAllowlist(host)
		if h == "" {
			continue
		}
		hosts[h] = struct{}{}
	}
	if len(hosts) == 0 {
		return nil
	}
	return hosts
}

func normalizeHostForAllowlist(raw string) string {
	trimmed := strings.TrimSpace(strings.ToLower(raw))
	if trimmed == "" {
		return ""
	}

	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		u, err := url.Parse(trimmed)
		if err != nil || u == nil {
			return ""
		}
		if u.Host == "" {
			return ""
		}
		trimmed = u.Host
	}

	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		return strings.ToLower(host)
	}
	if strings.Contains(trimmed, "/") {
		trimmed = strings.Split(trimmed, "/")[0]
	}
	return strings.TrimSpace(trimmed)
}

func (h *Handler) isAllowedProviderHost(req *http.Request) bool {
	if h == nil || len(h.allowedHosts) == 0 || req == nil || req.URL == nil {
		return true
	}
	host := strings.ToLower(req.URL.Hostname())
	if host == "" {
		return false
	}

	for pattern := range h.allowedHosts {
		if strings.EqualFold(host, pattern) {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*.")
			if suffix != "" && strings.HasSuffix(host, "."+suffix) {
				return true
			}
		}
	}
	return false
}

func estimateTokenCount(text string) int {
	if len(text) == 0 {
		return 0
	}
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0
	}

	estByChars := len(trimmed) / 4
	wordCount := len(strings.Fields(trimmed))
	if wordCount > estByChars {
		return wordCount
	}
	return estByChars
}

func copyHeadersWithoutContentLength(dst, src http.Header) {
	for k, vv := range src {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (h *Handler) auditPayload(payload []byte, piiFindings []pii.Finding, decision dlp.Decision) string {
	sanitized := string(payload)
	if h != nil && h.dlpSvc != nil && decision.Action == dlp.DLPActionSanitize {
		sanitized = h.dlpSvc.Sanitize(sanitized, piiFindings)
	}

	for _, p := range pii.Patterns {
		sanitized = p.Pattern.ReplaceAllString(sanitized, "[redacted:"+p.Name+"]")
	}
	if len(sanitized) > maxAuditBodyChars {
		return sanitized[:maxAuditBodyChars] + "..."
	}
	return sanitized
}

func appendUniqueTypes(existing []string, additional []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(additional))
	out := make([]string, 0, len(existing)+len(additional))
	for _, t := range existing {
		if _, ok := seen[t]; ok || t == "" {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	for _, t := range additional {
		if _, ok := seen[t]; ok || t == "" {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func (h *Handler) dlpTypes(findings []dlp.Finding) []string {
	if h == nil || h.dlpSvc == nil {
		return nil
	}
	return h.dlpSvc.Types(findings)
}

func requestedCompletionTokens(req chatRequest) int {
	if req.MaxCompletionTokens > 0 {
		return req.MaxCompletionTokens
	}
	if req.MaxTokensToSample > 0 {
		return req.MaxTokensToSample
	}
	if req.MaxTokens > 0 {
		return req.MaxTokens
	}
	return 0
}

func (h *Handler) resolveCompletionTokenLimit(requested int) (int, error) {
	if h == nil || h.maxCompletionTokens <= 0 {
		return requested, nil
	}
	if requested <= 0 {
		return h.maxCompletionTokens, nil
	}
	if requested > h.maxCompletionTokens {
		return 0, fmt.Errorf("max completion tokens exceeds allowed limit")
	}
	return requested, nil
}

func (h *Handler) mergePolicyAction(policyAction string, dlpAction dlp.Action) string {
	if policyAction == string(policy.ActionBlocked) {
		return string(policy.ActionBlocked)
	}
	switch dlpAction {
	case dlp.DLPActionBlock:
		return string(policy.ActionBlocked)
	case dlp.DLPActionSanitize:
		return string(dlp.DLPActionSanitize)
	case dlp.DLPActionAllow:
		fallthrough
	default:
		if policyAction == "" {
			return string(policy.ActionAllowed)
		}
		return policyAction
	}
}

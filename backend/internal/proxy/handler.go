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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/budget"
	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/firewall"
	"github.com/shadowai/backend/internal/governance"
	"github.com/shadowai/backend/internal/metrics"
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
	firewallPipeline *firewall.Pipeline
	// PR-A: privacy. Applies to every audit_log write через h.auditLog().
	auditPayloadMode audit.PayloadMode
	// PR-G1: enforcement point для Provider/Model Governance. nil →
	// governance не применяется (Core build / dev). Evaluate
	// вызывается после model resolve, до firewall — deny
	// короткозамыкает запрос. Type — core interface (Evaluator);
	// enterprise-реализация (*governance.Service) satisfies его.
	governanceSvc governance.Evaluator
	// PR-G1: admin-event writer для governance_deny / governance
	// CRUD. nil → админ-события не пишутся (Core build / dev).
	adminAudit adminaudit.Recorder
	// PR-F7.1: streaming transport mode (см. docs/rfcs/2026-04-pr-f7-*).
	// Допустимые значения: "" (== "buffered") | "incremental" | "shadow".
	// Default пустой = buffered (исторический path unchanged).
	// Shadow в F7.1 эквивалентен buffered (зарезервирован под F7.2+).
	streamingMode string
	// PR-F7.2: кэшированное решение capability-проверки. Вычисляется
	// один раз в SetStreamingMode через DecideStreamingCapability
	// над текущим firewallPipeline. Read-only после SetStreamingMode —
	// безопасно читать concurrent'но. Если IsFallback() → весь
	// stream идёт через buffered path с audit-маркером
	// streaming_buffered_fallback.
	streamingCapability CapabilityDecision
	// Замечание (PR-F7.2 review fix): ранее существовало поле
	// streamingFallbackLastReason, которое мутировалось per-request.
	// Это был data-race bug (net/http обрабатывает concurrent
	// requests в своих goroutine'ах). Удалено. Fallback reason
	// теперь request-local переменная в каждой streaming-ветви,
	// возвращаемая из shouldUseIncrementalStream.
}

// SetStreamingMode — F7.1: настройка transport mode после
// конструктора. Оставлено как setter (не constructor arg), чтобы не
// ломать существующих callers NewHandler.
//
// PR-F7.2: дополнительно вычисляет streamingCapability из
// firewallPipeline. Это позволяет capability-check в
// shouldUseIncrementalStream работать без повторного walk'а
// pipeline'а на каждый запрос.
func (h *Handler) SetStreamingMode(mode string) {
	h.streamingMode = mode
	h.streamingCapability = DecideStreamingCapability(h.firewallPipeline)
}

// NewHandler creates a new multi-provider proxy handler.
//
// governanceSvc / adminAudit — опциональные (nil = фича off).
// Передача nil в тестах и dev'е безопасна и сохраняет исторический
// proxy-flow без governance enforcement.
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
	firewallPipeline *firewall.Pipeline,
	auditPayloadMode audit.PayloadMode,
	governanceSvc governance.Evaluator,
	adminAudit adminaudit.Recorder,
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
		firewallPipeline: firewallPipeline,
		auditPayloadMode: auditPayloadMode,
		governanceSvc:    governanceSvc,
		adminAudit:       adminAudit,
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

	// PR-4: request-scoped накопитель shadow-решений. Заполняется после
	// каждого firewall.Inspect* через appendShadowDecisions(r.Context(), ...)
	// и автоматически сериализуется в audit_logs.shadow_decisions_json
	// через h.auditLog(r.Context(), ...).
	r = r.WithContext(withShadowSlot(r.Context()))

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

	// 3.6. PR-G1: Provider/Model Governance enforcement.
	// Evaluate стоит после isModelSupported (чтобы провайдер вообще
	// понимал модель) и ДО firewall/budget/DLP — governance-deny
	// короткозамыкает запрос, не тратя токены на firewall-scan.
	// nil governanceSvc (Core build / dev) обходит enforcement.
	if h.governanceSvc != nil {
		if dec, _ := h.governanceSvc.Evaluate(r.Context(), claims.Role, providerName, model); dec.Kind == governance.DecisionDeny {
			h.recordGovernanceDeny(r, claims, providerName, model, dec)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":     "model denied by governance policy",
				"code":      dec.Code,
				"reason":    dec.Reason,
				"provider":  providerName,
				"model":     model,
				"policy_id": dec.PolicyID,
			})
			return
		}
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

	// 3.9. Firewall Pipeline — request inspection
	firewallFlagged := false
	if h.firewallPipeline != nil {
		fwMessages := make([]firewall.Message, 0, len(chatReq.Messages))
		for _, m := range chatReq.Messages {
			fwMessages = append(fwMessages, firewall.Message{Role: m.Role, Content: m.Content})
		}
		fwPayload := &firewall.Payload{
			Text:     allText,
			Messages: fwMessages,
			Model:    model,
			Provider: providerName,
			UserID:   claims.UserID,
			Phase:    firewall.PhaseRequest,
			Meta:     extractFirewallMeta(r),
		}
		fwDecision, fwErr := h.firewallPipeline.InspectRequest(r.Context(), fwPayload)
		if fwErr != nil {
			http.Error(w, `{"error":"firewall error"}`, http.StatusInternalServerError)
			return
		}
		appendShadowDecisions(r.Context(), fwDecision.ShadowDecisions)
		if fwDecision.Action == firewall.ActionBlock {
			if h.auditSvc != nil {
				h.auditLog(r.Context(), &domain.AuditLog{
					ID: uuid.New().String(), UserID: claims.UserID,
					RequestBody:  sanitizePayload(bodyBytes),
					Model:        model, Provider: providerName,
					Endpoint:     endpoint, StatusCode: 403,
					PIIDetected:  len(fwDecision.Findings) > 0,
					PolicyAction: "blocked",
					DurationMs:   int(time.Since(start).Milliseconds()),
				})
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":     "blocked by firewall",
				"reason":    fwDecision.Reason,
				"inspector": fwDecision.InspectorName,
			})
			return
		}
		// ActionFlag: помечаем для корреляции в финальной audit-записи (без отдельной записи).
		if fwDecision.Action == firewall.ActionFlag {
			firewallFlagged = true
		}
		// ActionSanitize: санитизируем как локальный allText, так и outbound body через DLP.
		if fwDecision.Action == firewall.ActionSanitize && fwDecision.SanitizedText != "" {
			allText = fwDecision.SanitizedText
			if h.dlpSvc != nil {
				bodyBytes = sanitizeChatRequestBody(bodyBytes, h.dlpSvc)
				// Перепарсить для единообразия downstream-кода
				if err := json.Unmarshal(bodyBytes, &chatReq); err == nil {
					_ = chatReq
				}
			}
		}
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
		h.auditLog(r.Context(), &domain.AuditLog{
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

	policyAction := applyFlagCorrelation(h.mergePolicyAction(string(evalResult.Action), requestDecision.Action), firewallFlagged)
	if evalResult.Action == policy.ActionBlocked {
		h.auditLog(r.Context(), &domain.AuditLog{
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
		h.auditLog(r.Context(), &domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: h.auditPayload(bodyBytes, findings, requestDecision),
			Model:       model, Provider: providerName,
			Endpoint: endpoint, StatusCode: 402,
			PIIDetected: piiDetected, PIITypes: requestPIITypes,
			PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})
		metrics.RecordBudgetBlock(false)
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
		// PR-F7.1 incremental transport branch. Активируется ТОЛЬКО
		// при STREAMING_MODE=incremental и наличии paired adapter'а
		// для провайдера (см. streaming.AdapterForProvider). Real-time
		// passthrough через normalized event layer, БЕЗ response-side
		// firewall/DLP inspection (inspection придёт в PR-F7.2).
		// Budget / usage / audit сохраняются — accumulated bytes
		// скармливаются существующему parseStreamingUsage.
		adapter, useIncremental, streamingFallbackReason := h.shouldUseIncrementalStream(providerName)
		if useIncremental {
			metrics.RecordStreamingMode("incremental", providerName)
			// PR-F7.2: inspection engine заменяет transport-only
			// F7.1 поведение. firewallPipeline / dlpSvc прокидываются
			// как есть; capability уже проверена на уровне
			// shouldUseIncrementalStream (CM+judge → buffered_fallback).
			engine := newIncrementalEngine(
				h.firewallPipeline, h.dlpSvc,
				model, providerName, claims.UserID,
			)
			res := h.runIncrementalStreamTransport(
				r.Context(), w, resp.Header, resp.Body, resp.StatusCode,
				providerName, adapter, engine,
			)
			// Post-stream accounting (те же правила, что в buffered path).
			streamUsage, parseErr := parseStreamingUsage(provider, res.Accumulated, model)
			if parseErr != nil || !streamUsage.Found {
				metrics.RecordStreamUsageParseFail(providerName)
			}
			promptTokens := streamUsage.PromptTokens
			completionTokens := streamUsage.CompletionTokens
			totalTokens := streamUsage.TotalTokens
			cost := streamUsage.CostUSD
			if cost > 0 {
				_ = h.budgetSvc.RecordUsage(r.Context(), claims.UserID, cost, totalTokens)
			}
			// PR-F7.3: structured audit fields (RFC §11).
			//   policy_action — policy/security verdict (block over
			//                   allow если inspector block'нул; иначе
			//                   flagged если flagged; иначе original).
			//   outcome       — transport-level итог через
			//                   classifyIncrementalOutcome.
			//   fallback_reason — "" (fallback не случился, мы
			//                     в incremental ветке).
			//   usage_source  — final / none через classifyUsageSource.
			// StatusCode отражает audit-side classification:
			// Block→403, Transport error→502, прочее→resp.StatusCode.
			overBudget := false
			if allowedAfter, err := h.budgetSvc.CheckBudgetAfterUsage(r.Context(), claims.UserID, totalTokens, cost); err == nil && !allowedAfter {
				metrics.RecordBudgetBlock(true)
				overBudget = true
			}
			auditOutcome := classifyIncrementalOutcome(res.Blocked, res.TransportErr != nil, parseErr, overBudget, res.Flagged)
			// F7.3 invariant: policy_action = security verdict, independent
			// of transport outcome. Вычисляем ДО outcome branching, чтобы
			// transport error не подавил already-observed flag/block.
			auditPolicyAction := incrementalSecurityVerdict(policyAction, res.Blocked, res.Flagged)
			// StatusCode: transport-side (может расходиться с client HTTP
			// status — например, 403 в audit при client-500 incremental block).
			auditStatus := resp.StatusCode
			if res.Blocked {
				auditStatus = http.StatusForbidden
			} else if res.TransportErr != nil {
				auditStatus = http.StatusBadGateway
			}
			h.auditLog(r.Context(), &domain.AuditLog{
				ID: uuid.New().String(), UserID: claims.UserID,
				RequestBody:  h.auditPayload(bodyBytes, findings, requestDecision),
				ResponseBody: h.auditPayload(res.Accumulated, nil, dlp.Decision{Action: dlp.DLPActionAllow}),
				Model:        model, Provider: providerName, Endpoint: endpoint,
				StatusCode:   auditStatus,
				PromptTokens: promptTokens, CompletionTokens: completionTokens,
				TotalTokens: totalTokens, CostUSD: cost,
				PIIDetected: piiDetected, PIITypes: piiTypes,
				PolicyAction:   auditPolicyAction,
				Outcome:        auditOutcome,
				UsageSource:    classifyUsageSource(streamUsage.Found, parseErr),
				DurationMs:     int(time.Since(start).Milliseconds()),
			})
			return
		}
		metrics.RecordStreamingMode("buffered", providerName)
		// ВНИМАНИЕ: текущая реализация streaming НЕ является real-time passthrough.
		// Чтобы гарантировать enforcement DLP и firewall на response, handler
		// буферизует весь upstream-stream, затем прогоняет его через inspectors
		// и только после этого отдаёт клиенту. Это даёт:
		//   - корректную блокировку вредоносных ответов (never leak)
		//   - sanitization секретов в response
		//   - post-call budget accounting по ParseResponse
		// Ценой является отсутствие real-time chunk delivery. Для low-latency UX
		// потребуется incremental scanning (см. roadmap).
		respBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, `{"error":"read upstream"}`, http.StatusBadGateway)
			return
		}

		accumulated := string(respBytes)

		// Firewall Pipeline — response inspection (streaming)
		if h.firewallPipeline != nil {
			fwPayload := &firewall.Payload{
				Text: accumulated, Model: model, Provider: providerName,
				UserID: claims.UserID, Phase: firewall.PhaseResponse,
			}
			fwDecision, fwErr := h.firewallPipeline.InspectResponse(r.Context(), fwPayload)
			if fwErr == nil {
				appendShadowDecisions(r.Context(), fwDecision.ShadowDecisions)
			}
			if fwErr == nil && fwDecision.Action == firewall.ActionBlock {
				if h.auditSvc != nil {
					h.auditLog(r.Context(), &domain.AuditLog{
						ID: uuid.New().String(), UserID: claims.UserID,
						RequestBody: sanitizePayload(bodyBytes), ResponseBody: sanitizePayload(respBytes),
						Model: model, Provider: providerName, Endpoint: endpoint,
						StatusCode: 403, PolicyAction: "blocked",
						DurationMs: int(time.Since(start).Milliseconds()),
					})
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "blocked by firewall", "reason": fwDecision.Reason,
					"inspector": fwDecision.InspectorName,
				})
				return
			}
			if fwErr == nil && fwDecision.Action == firewall.ActionFlag {
				firewallFlagged = true
			}
			if fwErr == nil && fwDecision.Action == firewall.ActionSanitize && fwDecision.SanitizedText != "" {
				accumulated = fwDecision.SanitizedText
				respBytes = []byte(accumulated)
			}
		}

		responseFindings := pii.Scan(accumulated)
		responseDecision := dlp.Decision{Action: dlp.DLPActionAllow}
		if h.dlpSvc != nil {
			responseDecision = h.dlpSvc.Evaluate(accumulated, responseFindings)
		}

		responsePolicyAction := applyFlagCorrelation(h.mergePolicyAction(policyAction, responseDecision.Action), firewallFlagged)
		responsePIITypes := appendUniqueTypes(piiTypes, pii.DetectedTypes(responseFindings))
		responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(requestDecision.Findings))
		responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(responseDecision.Findings))

		if responseDecision.Action == dlp.DLPActionBlock {
			// PR-F7.3: structured streaming fields. usage_source=none
			// (usage не parse'ится при block — early return).
			h.auditLog(r.Context(), &domain.AuditLog{
				ID: uuid.New().String(), UserID: claims.UserID,
				RequestBody:  h.auditPayload(bodyBytes, findings, requestDecision),
				ResponseBody: h.auditPayload(respBytes, responseFindings, responseDecision),
				Model:        model, Provider: providerName, Endpoint: endpoint,
				StatusCode:   resp.StatusCode,
				PIIDetected:  piiDetected || len(responseFindings) > 0, PIITypes: responsePIITypes,
				PolicyAction:   responsePolicyAction,
				Outcome:        classifyBufferedOutcome(responsePolicyAction, streamingFallbackReason != "", nil),
				FallbackReason: streamingFallbackReason,
				UsageSource:    UsageSourceNone,
				DurationMs:     int(time.Since(start).Milliseconds()),
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

		// Post-call budget accounting для streaming через provider-specific
		// SSE parser (см. internal/proxy/stream_usage_*.go).
		// parseStreamingUsage — soft-fail: Found=false не ошибка, это валидный
		// fallback path для провайдеров без include_usage поддержки.
		streamUsage, parseErr := parseStreamingUsage(provider, respBytes, model)
		// Метрика: usage не был успешно извлечён из потока. Включает как
		// real parser errors, так и soft-fail (Found=false).
		if parseErr != nil || !streamUsage.Found {
			metrics.RecordStreamUsageParseFail(providerName)
		}
		promptTokens := streamUsage.PromptTokens
		completionTokens := streamUsage.CompletionTokens
		totalTokens := streamUsage.TotalTokens
		cost := streamUsage.CostUSD
		recordUsage := func() {
			if cost > 0 {
				_ = h.budgetSvc.RecordUsage(r.Context(), claims.UserID, cost, totalTokens)
			}
		}

		// Post-call budget check. Работает даже при 0 tokens (защищает, если
		// пользователь уже превысил лимит прошлыми запросами).
		allowedAfter, err := h.budgetSvc.CheckBudgetAfterUsage(r.Context(), claims.UserID, totalTokens, cost)
		if err == nil && !allowedAfter {
			recordUsage()
			metrics.RecordBudgetBlock(true)
			// PR-F7.3: structured streaming fields. Hard budget block
			// в buffered → outcome=stream_blocked (fallback marker
			// доминирует если mode был incremental).
			h.auditLog(r.Context(), &domain.AuditLog{
				ID: uuid.New().String(), UserID: claims.UserID,
				RequestBody:  h.auditPayload(bodyBytes, findings, requestDecision),
				ResponseBody: h.auditPayload(responsePayload, responseFindings, responseDecision),
				Model:        model, Provider: providerName, Endpoint: endpoint,
				StatusCode:   http.StatusPaymentRequired,
				PromptTokens: promptTokens, CompletionTokens: completionTokens,
				TotalTokens: totalTokens, CostUSD: cost,
				PIIDetected:  piiDetected || len(responseFindings) > 0, PIITypes: responsePIITypes,
				PolicyAction:   policyAction,
				Outcome:        bufferedBudgetBlockOutcome(streamingFallbackReason != ""),
				FallbackReason: streamingFallbackReason,
				UsageSource:    classifyUsageSource(streamUsage.Found, parseErr),
				DurationMs:     int(time.Since(start).Milliseconds()),
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			json.NewEncoder(w).Encode(map[string]string{"error": "budget exceeded"})
			return
		}
		recordUsage()

		copyHeadersWithoutContentLength(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		// PR-F7.3: structured streaming fields для buffered path.
		// policy_action остаётся чистым verdict'ом (block/flag/
		// sanitize/allow); fallback/transport/usage перешли в
		// отдельные поля.
		h.auditLog(r.Context(), &domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody:  h.auditPayload(bodyBytes, findings, requestDecision),
			ResponseBody: h.auditPayload(responsePayload, responseFindings, responseDecision),
			Model:        model, Provider: providerName, Endpoint: endpoint,
			StatusCode:   resp.StatusCode,
			PromptTokens: promptTokens, CompletionTokens: completionTokens,
			TotalTokens: totalTokens, CostUSD: cost,
			PIIDetected:  piiDetected || len(responseFindings) > 0, PIITypes: responsePIITypes,
			PolicyAction:   policyAction,
			Outcome:        classifyBufferedOutcome(policyAction, streamingFallbackReason != "", parseErr),
			FallbackReason: streamingFallbackReason,
			UsageSource:    classifyUsageSource(streamUsage.Found, parseErr),
			DurationMs:     int(time.Since(start).Milliseconds()),
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

	// Firewall Pipeline — response inspection (non-streaming)
	if h.firewallPipeline != nil {
		fwPayload := &firewall.Payload{
			Text: string(respBody), Model: model, Provider: providerName,
			UserID: claims.UserID, Phase: firewall.PhaseResponse,
		}
		fwDecision, fwErr := h.firewallPipeline.InspectResponse(r.Context(), fwPayload)
		if fwErr == nil {
			appendShadowDecisions(r.Context(), fwDecision.ShadowDecisions)
		}
		if fwErr == nil && fwDecision.Action == firewall.ActionBlock {
			if h.auditSvc != nil {
				h.auditLog(r.Context(), &domain.AuditLog{
					ID: uuid.New().String(), UserID: claims.UserID,
					RequestBody: sanitizePayload(bodyBytes), ResponseBody: sanitizePayload(respBody),
					Model: model, Provider: providerName, Endpoint: endpoint,
					StatusCode: 403, PolicyAction: "blocked",
					DurationMs: int(time.Since(start).Milliseconds()),
				})
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "blocked by firewall", "reason": fwDecision.Reason,
				"inspector": fwDecision.InspectorName,
			})
			return
		}
		if fwErr == nil && fwDecision.Action == firewall.ActionFlag {
			firewallFlagged = true
		}
		if fwErr == nil && fwDecision.Action == firewall.ActionSanitize && fwDecision.SanitizedText != "" {
			respBody = []byte(fwDecision.SanitizedText)
		}
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
		metrics.RecordBudgetBlock(false)
		h.auditLog(r.Context(), &domain.AuditLog{
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

	responsePolicyAction := applyFlagCorrelation(h.mergePolicyAction(policyAction, responseDecision.Action), firewallFlagged)
	responsePIITypes := appendUniqueTypes(piiTypes, pii.DetectedTypes(responseFindings))
	responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(requestDecision.Findings))
	responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(responseDecision.Findings))

	if responseDecision.Action == dlp.DLPActionBlock {
		recordUsage()
		h.auditLog(r.Context(), &domain.AuditLog{
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
	h.auditLog(r.Context(), &domain.AuditLog{
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
			h.auditLog(r.Context(), &domain.AuditLog{
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
			h.auditLog(r.Context(), &domain.AuditLog{
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
			h.auditLog(r.Context(), &domain.AuditLog{
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
		h.auditLog(r.Context(), &domain.AuditLog{
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

	// PR-4: request-scoped shadow-accumulator. См. ProxyChat для деталей.
	r = r.WithContext(withShadowSlot(r.Context()))

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

	// 3.9. Firewall Pipeline — request inspection
	firewallFlagged := false
	if h.firewallPipeline != nil {
		fwMessages := make([]firewall.Message, 0, len(chatReq.Messages))
		for _, m := range chatReq.Messages {
			fwMessages = append(fwMessages, firewall.Message{Role: m.Role, Content: m.Content})
		}
		fwPayload := &firewall.Payload{
			Text:     allText,
			Messages: fwMessages,
			Model:    model,
			Provider: "unified",
			UserID:   claims.UserID,
			Phase:    firewall.PhaseRequest,
			Meta:     extractFirewallMeta(r),
		}
		fwDecision, fwErr := h.firewallPipeline.InspectRequest(r.Context(), fwPayload)
		if fwErr != nil {
			http.Error(w, `{"error":"firewall error"}`, http.StatusInternalServerError)
			return
		}
		appendShadowDecisions(r.Context(), fwDecision.ShadowDecisions)
		if fwDecision.Action == firewall.ActionBlock {
			if h.auditSvc != nil {
				h.auditLog(r.Context(), &domain.AuditLog{
					ID: uuid.New().String(), UserID: claims.UserID,
					RequestBody:  sanitizePayload(bodyBytes),
					Model:        model, Provider: "unified",
					Endpoint:     "/proxy/chat", StatusCode: 403,
					PIIDetected:  len(fwDecision.Findings) > 0,
					PolicyAction: "blocked",
					DurationMs:   int(time.Since(start).Milliseconds()),
				})
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":     "blocked by firewall",
				"reason":    fwDecision.Reason,
				"inspector": fwDecision.InspectorName,
			})
			return
		}
		if fwDecision.Action == firewall.ActionFlag {
			firewallFlagged = true
		}
		if fwDecision.Action == firewall.ActionSanitize && fwDecision.SanitizedText != "" {
			allText = fwDecision.SanitizedText
			if h.dlpSvc != nil {
				bodyBytes = sanitizeChatRequestBody(bodyBytes, h.dlpSvc)
				if err := json.Unmarshal(bodyBytes, &chatReq); err == nil {
					_ = chatReq
				}
			}
		}
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
		h.auditLog(r.Context(), &domain.AuditLog{
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

	policyAction := applyFlagCorrelation(h.mergePolicyAction(string(evalResult.Action), requestDecision.Action), firewallFlagged)
	if evalResult.Action == policy.ActionBlocked {
		h.auditLog(r.Context(), &domain.AuditLog{
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
		h.auditLog(r.Context(), &domain.AuditLog{
			ID: uuid.New().String(), UserID: claims.UserID,
			RequestBody: h.auditPayload(bodyBytes, findings, requestDecision),
			Model:       model, Provider: "unified", Endpoint: "/proxy/chat",
			StatusCode: 402, PIIDetected: piiDetected, PIITypes: requestPIITypes,
			PolicyAction: policyAction, DurationMs: int(time.Since(start).Milliseconds()),
		})
		metrics.RecordBudgetBlock(false)
		http.Error(w, `{"error":"budget exceeded"}`, http.StatusPaymentRequired)
		return
	}

	// 7. Route — get ordered candidates
	candidates, err := h.router.Route(r.Context(), model)
	if err != nil || len(candidates) == 0 {
		http.Error(w, `{"error":"no providers available"}`, http.StatusServiceUnavailable)
		return
	}

	// 7.5. PR-G1: governance filter. Удаляем candidates, которые
	// запрещены active policy. Если после фильтрации пусто —
	// возвращаем 403 governance_deny (не 503), чтобы оператор чётко
	// видел причину отказа. Первый denied candidate пишется в
	// admin_event_logs как representative event.
	if h.governanceSvc != nil {
		allowed := candidates[:0]
		var firstDeny governance.Decision
		var firstDenyProvider, firstDenyModel string
		for _, cand := range candidates {
			cm := model
			if cm == "" {
				cm = cand.Provider.DefaultModel()
			}
			dec, _ := h.governanceSvc.Evaluate(r.Context(), claims.Role, cand.Name, cm)
			if dec.Kind == governance.DecisionAllow {
				allowed = append(allowed, cand)
				continue
			}
			if firstDeny.Code == "" {
				firstDeny = dec
				firstDenyProvider = cand.Name
				firstDenyModel = cm
			}
		}
		candidates = allowed
		if len(candidates) == 0 {
			h.recordGovernanceDeny(r, claims, firstDenyProvider, firstDenyModel, firstDeny)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":     "model denied by governance policy",
				"code":      firstDeny.Code,
				"reason":    firstDeny.Reason,
				"provider":  firstDenyProvider,
				"model":     firstDenyModel,
				"policy_id": firstDeny.PolicyID,
			})
			return
		}
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
			// PR-F7.1: incremental transport branch (см. ProxyChat
			// аналог + handler_streaming_incremental.go). Real-time
			// passthrough через normalized event layer; response-side
			// inspection отключена в F7.1 (F7.2 добавит).
			adapter, useIncremental, streamingFallbackReason := h.shouldUseIncrementalStream(candidate.Name)
			if useIncremental {
				metrics.RecordStreamingMode("incremental", candidate.Name)
				engine := newIncrementalEngine(
					h.firewallPipeline, h.dlpSvc,
					providerModel, candidate.Name, claims.UserID,
				)
				res := h.runIncrementalStreamTransport(
					r.Context(), w, resp.Header, resp.Body, resp.StatusCode,
					candidate.Name, adapter, engine,
				)
				resp.Body.Close()
				streamUsage, parseErr := parseStreamingUsage(provider, res.Accumulated, providerModel)
				if parseErr != nil || !streamUsage.Found {
					metrics.RecordStreamUsageParseFail(candidate.Name)
				}
				promptTokens := streamUsage.PromptTokens
				completionTokens := streamUsage.CompletionTokens
				totalTokens := streamUsage.TotalTokens
				cost := streamUsage.CostUSD
				if cost > 0 {
					_ = h.budgetSvc.RecordUsage(r.Context(), claims.UserID, cost, totalTokens)
				}
				// PR-F7.3: structured audit fields — симметрично
				// ProxyChat incremental ветке.
				overBudget := false
				if allowedAfter, err := h.budgetSvc.CheckBudgetAfterUsage(r.Context(), claims.UserID, totalTokens, cost); err == nil && !allowedAfter {
					metrics.RecordBudgetBlock(true)
					overBudget = true
				}
				auditOutcome := classifyIncrementalOutcome(res.Blocked, res.TransportErr != nil, parseErr, overBudget, res.Flagged)
				// F7.3 invariant — симметрично ProxyChat.
				auditPolicyAction := incrementalSecurityVerdict(policyAction, res.Blocked, res.Flagged)
				auditStatus := resp.StatusCode
				if res.Blocked {
					auditStatus = http.StatusForbidden
				} else if res.TransportErr != nil {
					auditStatus = http.StatusBadGateway
				}
				h.auditLog(r.Context(), &domain.AuditLog{
					ID: uuid.New().String(), UserID: claims.UserID,
					RequestBody:  h.auditPayload(requestPayload, findings, requestDecision),
					ResponseBody: h.auditPayload(res.Accumulated, nil, dlp.Decision{Action: dlp.DLPActionAllow}),
					Model:        providerModel, Provider: candidate.Name, Endpoint: "/proxy/chat",
					StatusCode:   auditStatus,
					PromptTokens: promptTokens, CompletionTokens: completionTokens,
					TotalTokens: totalTokens, CostUSD: cost,
					PIIDetected: piiDetected, PIITypes: piiTypes,
					PolicyAction:   auditPolicyAction,
					Outcome:        auditOutcome,
					UsageSource:    classifyUsageSource(streamUsage.Found, parseErr),
					DurationMs:     int(time.Since(start).Milliseconds()),
				})
				return
			}
			metrics.RecordStreamingMode("buffered", candidate.Name)
			respBytes, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				lastErr = err
				continue
			}

			accumulated := string(respBytes)

			// Firewall Pipeline — response inspection (streaming)
			if h.firewallPipeline != nil {
				fwPayload := &firewall.Payload{
					Text: accumulated, Model: providerModel, Provider: candidate.Name,
					UserID: claims.UserID, Phase: firewall.PhaseResponse,
				}
				fwDecision, fwErr := h.firewallPipeline.InspectResponse(r.Context(), fwPayload)
				if fwErr == nil {
					appendShadowDecisions(r.Context(), fwDecision.ShadowDecisions)
				}
				if fwErr == nil && fwDecision.Action == firewall.ActionBlock {
					if h.auditSvc != nil {
						h.auditLog(r.Context(), &domain.AuditLog{
							ID: uuid.New().String(), UserID: claims.UserID,
							RequestBody: sanitizePayload(bodyBytes), ResponseBody: sanitizePayload(respBytes),
							Model: providerModel, Provider: candidate.Name, Endpoint: "/proxy/chat",
							StatusCode: 403, PolicyAction: "blocked",
							DurationMs: int(time.Since(start).Milliseconds()),
						})
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]string{
						"error": "blocked by firewall", "reason": fwDecision.Reason,
						"inspector": fwDecision.InspectorName,
					})
					return
				}
				if fwErr == nil && fwDecision.Action == firewall.ActionFlag {
					firewallFlagged = true
				}
				if fwErr == nil && fwDecision.Action == firewall.ActionSanitize && fwDecision.SanitizedText != "" {
					accumulated = fwDecision.SanitizedText
					respBytes = []byte(accumulated)
				}
			}

			responseFindings := pii.Scan(accumulated)
			responseDecision := dlp.Decision{Action: dlp.DLPActionAllow}
			if h.dlpSvc != nil {
				responseDecision = h.dlpSvc.Evaluate(accumulated, responseFindings)
			}
			responsePolicyAction := applyFlagCorrelation(h.mergePolicyAction(policyAction, responseDecision.Action), firewallFlagged)
			responsePIITypes := appendUniqueTypes(piiTypes, pii.DetectedTypes(responseFindings))
			responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(requestDecision.Findings))
			responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(responseDecision.Findings))

			if responseDecision.Action == dlp.DLPActionBlock {
				// PR-F7.3: structured streaming fields. См. ProxyChat аналог.
				h.auditLog(r.Context(), &domain.AuditLog{
					ID: uuid.New().String(), UserID: claims.UserID,
					RequestBody: h.auditPayload(requestPayload, findings, requestDecision), ResponseBody: h.auditPayload(respBytes, responseFindings, responseDecision),
					Model: providerModel, Provider: candidate.Name, Endpoint: "/proxy/chat",
					StatusCode:   resp.StatusCode,
					PromptTokens: 0, CompletionTokens: 0,
					TotalTokens:  0, CostUSD: 0,
					PIIDetected:  piiDetected || len(responseFindings) > 0, PIITypes: responsePIITypes,
					PolicyAction:   responsePolicyAction,
					Outcome:        classifyBufferedOutcome(responsePolicyAction, streamingFallbackReason != "", nil),
					FallbackReason: streamingFallbackReason,
					UsageSource:    UsageSourceNone,
					DurationMs:     int(time.Since(start).Milliseconds()),
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

			// Post-call budget accounting для UnifiedChat streaming.
			// См. комментарий в ProxyChat streaming.
			streamUsage, parseErr := parseStreamingUsage(provider, respBytes, providerModel)
			if parseErr != nil || !streamUsage.Found {
				metrics.RecordStreamUsageParseFail(candidate.Name)
			}
			promptTokens := streamUsage.PromptTokens
			completionTokens := streamUsage.CompletionTokens
			totalTokens := streamUsage.TotalTokens
			cost := streamUsage.CostUSD
			recordStreamUsage := func() {
				if cost > 0 {
					_ = h.budgetSvc.RecordUsage(r.Context(), claims.UserID, cost, totalTokens)
				}
			}
			allowedAfter, err := h.budgetSvc.CheckBudgetAfterUsage(r.Context(), claims.UserID, totalTokens, cost)
			if err == nil && !allowedAfter {
				recordStreamUsage()
				metrics.RecordBudgetBlock(true)
				// PR-F7.3: structured streaming fields. См. ProxyChat аналог.
				h.auditLog(r.Context(), &domain.AuditLog{
					ID: uuid.New().String(), UserID: claims.UserID,
					RequestBody:  h.auditPayload(requestPayload, findings, requestDecision),
					ResponseBody: h.auditPayload(responsePayload, responseFindings, responseDecision),
					Model:        providerModel, Provider: candidate.Name, Endpoint: "/proxy/chat",
					StatusCode:   http.StatusPaymentRequired,
					PromptTokens: promptTokens, CompletionTokens: completionTokens,
					TotalTokens: totalTokens, CostUSD: cost,
					PIIDetected:  piiDetected || len(responseFindings) > 0, PIITypes: responsePIITypes,
					PolicyAction:   policyAction,
					Outcome:        bufferedBudgetBlockOutcome(streamingFallbackReason != ""),
					FallbackReason: streamingFallbackReason,
					UsageSource:    classifyUsageSource(streamUsage.Found, parseErr),
					DurationMs:     int(time.Since(start).Milliseconds()),
				})
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPaymentRequired)
				json.NewEncoder(w).Encode(map[string]string{"error": "budget exceeded"})
				return
			}
			recordStreamUsage()

			// PR-F7.3: structured streaming fields. См. ProxyChat аналог.
			h.auditLog(r.Context(), &domain.AuditLog{
				ID: uuid.New().String(), UserID: claims.UserID,
				RequestBody: h.auditPayload(requestPayload, findings, requestDecision), ResponseBody: h.auditPayload(responsePayload, responseFindings, responseDecision),
				Model: providerModel, Provider: candidate.Name, Endpoint: "/proxy/chat",
				StatusCode:   resp.StatusCode,
				PromptTokens: promptTokens, CompletionTokens: completionTokens,
				TotalTokens: totalTokens, CostUSD: cost,
				PIIDetected:  piiDetected || len(responseFindings) > 0, PIITypes: responsePIITypes,
				PolicyAction:   policyAction,
				Outcome:        classifyBufferedOutcome(policyAction, streamingFallbackReason != "", parseErr),
				FallbackReason: streamingFallbackReason,
				UsageSource:    classifyUsageSource(streamUsage.Found, parseErr),
				DurationMs:     int(time.Since(start).Milliseconds()),
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
			metrics.RecordBudgetBlock(false)
			h.auditLog(r.Context(), &domain.AuditLog{
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

		// Firewall Pipeline — response inspection (non-streaming)
		if h.firewallPipeline != nil {
			fwPayload := &firewall.Payload{
				Text: string(respBody), Model: providerModel, Provider: candidate.Name,
				UserID: claims.UserID, Phase: firewall.PhaseResponse,
			}
			fwDecision, fwErr := h.firewallPipeline.InspectResponse(r.Context(), fwPayload)
			if fwErr == nil {
				appendShadowDecisions(r.Context(), fwDecision.ShadowDecisions)
			}
			if fwErr == nil && fwDecision.Action == firewall.ActionBlock {
				if h.auditSvc != nil {
					h.auditLog(r.Context(), &domain.AuditLog{
						ID: uuid.New().String(), UserID: claims.UserID,
						RequestBody: sanitizePayload(bodyBytes), ResponseBody: sanitizePayload(respBody),
						Model: providerModel, Provider: candidate.Name, Endpoint: "/proxy/chat",
						StatusCode: 403, PolicyAction: "blocked",
						DurationMs: int(time.Since(start).Milliseconds()),
					})
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "blocked by firewall", "reason": fwDecision.Reason,
					"inspector": fwDecision.InspectorName,
				})
				return
			}
			if fwErr == nil && fwDecision.Action == firewall.ActionFlag {
				firewallFlagged = true
			}
			if fwErr == nil && fwDecision.Action == firewall.ActionSanitize && fwDecision.SanitizedText != "" {
				respBody = []byte(fwDecision.SanitizedText)
			}
		}

		responseFindings := pii.Scan(string(respBody))
		responseDecision := dlp.Decision{Action: dlp.DLPActionAllow}
		if h.dlpSvc != nil {
			responseDecision = h.dlpSvc.Evaluate(string(respBody), responseFindings)
		}
		responsePolicyAction := applyFlagCorrelation(h.mergePolicyAction(policyAction, responseDecision.Action), firewallFlagged)
		responsePIITypes := appendUniqueTypes(piiTypes, pii.DetectedTypes(responseFindings))
		responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(requestDecision.Findings))
		responsePIITypes = appendUniqueTypes(responsePIITypes, h.dlpTypes(responseDecision.Findings))

		if responseDecision.Action == dlp.DLPActionBlock {
			recordUsage()
			h.auditLog(r.Context(), &domain.AuditLog{
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

		h.auditLog(r.Context(), &domain.AuditLog{
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

// secretPatterns holds compiled regexps for DLP secret redaction in audit logs.
// Compiled once via sync.Once to avoid per-call overhead.
var (
	secretPatterns     []secretPattern
	secretPatternsOnce sync.Once
)

type secretPattern struct {
	name string
	re   *regexp.Regexp
}

func getSecretPatterns() []secretPattern {
	secretPatternsOnce.Do(func() {
		secretPatterns = []secretPattern{
			{"openai_key", regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`)},
			{"aws_key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
			{"anthropic_key", regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9\-_]{10,})`)},
			{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)},
			{"private_key", regexp.MustCompile(`(?s)-----BEGIN [A-Z ]+PRIVATE KEY-----[A-Za-z0-9+/=\s]*?-----END [A-Z ]+PRIVATE KEY-----`)},
			{"bearer_token", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}\b`)},
			{"api_secret", regexp.MustCompile(`(?i)\b(api[_-]?secret|secret[_-]?key|access[_-]?key)\s*[:=]\s*[A-Za-z0-9._/+]{16,}`)},
		}
	})
	return secretPatterns
}

func sanitizePayload(payload []byte) string {
	sanitized := string(payload)
	// PII patterns
	for _, p := range pii.Patterns {
		sanitized = p.Pattern.ReplaceAllString(sanitized, "[redacted:"+p.Name+"]")
	}
	// DLP secret patterns — redact API keys, tokens, private keys
	for _, sp := range getSecretPatterns() {
		sanitized = sp.re.ReplaceAllString(sanitized, "[redacted:"+sp.name+"]")
	}
	if len(sanitized) > maxAuditBodyChars {
		return sanitized[:maxAuditBodyChars] + "..."
	}
	return sanitized
}

// extractFirewallMeta собирает request-level метаданные для firewall-инспекторов.
// Клиент передаёт conversation_id через X-Conversation-ID header для корректного
// per-conversation скоупинга MultiTurnInspector. Без заголовка разные чаты
// одного UserID смешиваются.
func extractFirewallMeta(r *http.Request) map[string]string {
	meta := make(map[string]string)
	if convID := strings.TrimSpace(r.Header.Get("X-Conversation-ID")); convID != "" {
		// Ограничиваем длину чтобы исключить memory-abuse через header
		if len(convID) > 128 {
			convID = convID[:128]
		}
		meta["conversation_id"] = convID
	}
	return meta
}

// sanitizeChatRequestBody pass каждое message.content через dlpSvc.Sanitize
// и пересериализует chat request в JSON. Если парсинг/сериализация падает,
// возвращает исходное тело без модификации (fail-safe).
func sanitizeChatRequestBody(body []byte, dlpSvc *dlp.Service) []byte {
	if dlpSvc == nil || len(body) == 0 {
		return body
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}
	messagesVal, ok := raw["messages"].([]any)
	if !ok {
		return body
	}
	changed := false
	for i, m := range messagesVal {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		content, ok := msg["content"].(string)
		if !ok || content == "" {
			continue
		}
		sanitized := dlpSvc.Sanitize(content, pii.Scan(content))
		if sanitized != content {
			msg["content"] = sanitized
			messagesVal[i] = msg
			changed = true
		}
	}
	if !changed {
		return body
	}
	raw["messages"] = messagesVal
	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return out
}

// applyFlagCorrelation возвращает PolicyAction с учётом firewall-flag.
// Приоритет (от большего к меньшему): blocked > sanitized > warned > allowed.
// - blocked не меняется
// - sanitized не меняется (санитизация информативнее warn)
// - warned не меняется
// - allowed с флагом становится "warned"
func applyFlagCorrelation(action string, flagged bool) string {
	if !flagged {
		return action
	}
	switch action {
	case string(policy.ActionBlocked),
		string(dlp.DLPActionSanitize),
		string(policy.ActionWarned):
		return action
	}
	return string(policy.ActionWarned)
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

func (h *Handler) auditPayload(payload []byte, _ []pii.Finding, _ dlp.Decision) string {
	// ВАЖНО: piiFindings из вызова считаны по allText (конкатенации
	// message.content), а payload здесь — сырой JSON. Использовать те offsets
	// для Sanitize() привело бы к структурному повреждению JSON.
	// Пересчитываем findings по фактическому payload для корректной санитизации.
	sanitized := string(payload)
	if h != nil && h.dlpSvc != nil {
		bodyFindings := pii.Scan(sanitized)
		sanitized = h.dlpSvc.Sanitize(sanitized, bodyFindings)
	}
	// Also apply PII redaction
	for _, p := range pii.Patterns {
		sanitized = p.Pattern.ReplaceAllString(sanitized, "[redacted:"+p.Name+"]")
	}
	// Also apply DLP secret pattern redaction as defense-in-depth
	for _, sp := range getSecretPatterns() {
		sanitized = sp.re.ReplaceAllString(sanitized, "[redacted:"+sp.name+"]")
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

// FirewallStatus returns the current status of all firewall inspectors.
func (h *Handler) FirewallStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.firewallPipeline == nil {
		json.NewEncoder(w).Encode(map[string]any{"enabled": false, "inspectors": []any{}})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"enabled":    true,
		"inspectors": h.firewallPipeline.Status(),
	})
}

// recordGovernanceDeny — PR-G1: пишет admin_event_logs при отказе
// на уровне governance-политики. Nil-safe: при отсутствии adminAudit
// (dev/test) превращается в no-op.
//
// Шаблон события:
//
//	action   = "policy_deny"
//	resource = "provider_model"
//	target   = "<provider>/<model>" — стабильный composite-id для
//	           forensics-запросов "какие модели чаще всего блокируются".
//	metadata = { provider, model, code, policy_id, reason }
//
// success=false (это именно denied event). actor=claims.UserID
// (пользователь, чей запрос был отклонён), или nil если middleware
// не прикрепил claims (edge case — отсутствие actor уже само по себе
// forensic-сигнал).
func (h *Handler) recordGovernanceDeny(r *http.Request, claims *auth.Claims, provider, model string, dec governance.Decision) {
	if h.adminAudit == nil {
		return
	}
	var actor *string
	if claims != nil {
		id := claims.UserID
		actor = &id
	}
	h.adminAudit.Record(r.Context(), adminaudit.Event{
		ActorUserID: actor,
		Action:      "policy_deny",
		Resource:    "provider_model",
		TargetID:    provider + "/" + model,
		Path:        r.URL.Path,
		Method:      r.Method,
		StatusCode:  http.StatusForbidden,
		Success:     false,
		Metadata: map[string]any{
			"provider":  provider,
			"model":     model,
			"code":      dec.Code,
			"policy_id": dec.PolicyID,
			"reason":    dec.Reason,
		},
	})
}

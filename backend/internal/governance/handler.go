//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// Compiled only under -tags enterprise.

package governance

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/auth"
)

// Handler обслуживает admin CRUD для governance-политики.
// Маршруты (admin-only):
//
//	GET  /api/governance/policy — current active
//	PUT  /api/governance/policy — upsert (admin)
//
// Visibility endpoint POST/GET запросов deny логируется в
// admin_event_logs (см. proxy integration).
//
// Проектная политика: все ответы пишут admin_event_logs при успехе/
// ошибке изменений. Чтение (GET) тоже логируется — governance-
// политика сама по себе SOX-sensitive и compliance-trail нужен.
type Handler struct {
	svc        *Service
	adminAudit adminaudit.Recorder
}

func NewHandler(svc *Service, adminAudit adminaudit.Recorder) *Handler {
	return &Handler{svc: svc, adminAudit: adminAudit}
}

type policyResponse struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Mode         Mode           `json:"mode"`
	Rules        []ProviderRule `json:"rules"`
	RoleRules    []RoleRule     `json:"role_rules"`
	ContextRules []ContextRule  `json:"context_rules"`
	UpdatedAt    string         `json:"updated_at"`
	UpdatedBy    *string        `json:"updated_by,omitempty"`
	IsActive     bool           `json:"is_active"`
}

type emptyPolicyResponse struct {
	Configured bool `json:"configured"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type upsertRequest struct {
	Name         string         `json:"name"`
	Mode         Mode           `json:"mode"`
	Rules        []ProviderRule `json:"rules"`
	RoleRules    []RoleRule     `json:"role_rules"`
	ContextRules []ContextRule  `json:"context_rules"`
}

// GetPolicy — current active. Если ни одной политики нет (сырой
// deploy без seed), возвращаем 200 {"configured":false} — проще
// для UI, чем 404.
func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := h.svc.GetActive(r.Context())
	if err != nil {
		h.recordAdmin(r, "read", "", http.StatusInternalServerError, false, map[string]any{
			"error": "read_failed",
		})
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal"})
		return
	}
	if p == nil {
		writeJSON(w, http.StatusOK, emptyPolicyResponse{Configured: false})
		h.recordAdmin(r, "read", "", http.StatusOK, true, map[string]any{
			"configured": false,
		})
		return
	}
	resp := policyToResp(p)
	writeJSON(w, http.StatusOK, resp)
	h.recordAdmin(r, "read", p.ID, http.StatusOK, true, map[string]any{
		"mode":       p.Mode,
		"rule_count": len(p.Rules),
	})
}

// UpdatePolicy — upsert active. Admin-only (RBAC проверяется
// middleware — этот handler доверяет claims.Role).
func (h *Handler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	if claims.Role != auth.RoleAdmin {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: "forbidden"})
		return
	}

	var req upsertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if !req.Mode.IsValid() {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid mode"})
		h.recordAdmin(r, "update", "", http.StatusBadRequest, false, map[string]any{
			"error":         "invalid_mode",
			"attempted_mode": string(req.Mode),
		})
		return
	}

	p := &Policy{
		Name:         req.Name,
		Mode:         req.Mode,
		Rules:        req.Rules,
		RoleRules:    req.RoleRules,
		ContextRules: req.ContextRules,
	}
	saved, err := h.svc.Upsert(r.Context(), p, claims.UserID)
	if err != nil {
		var valErr *ValidationError
		if errors.As(err, &valErr) {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: valErr.Msg})
			h.recordAdmin(r, "update", "", http.StatusBadRequest, false, map[string]any{
				"error": "invalid_policy",
				"detail": valErr.Msg,
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal"})
		h.recordAdmin(r, "update", "", http.StatusInternalServerError, false, map[string]any{
			"error": "upsert_failed",
		})
		return
	}
	writeJSON(w, http.StatusOK, policyToResp(saved))
	h.recordAdmin(r, "update", saved.ID, http.StatusOK, true, map[string]any{
		"mode":               saved.Mode,
		"rule_count":         len(saved.Rules),
		"role_rule_count":    len(saved.RoleRules),
		"context_rule_count": len(saved.ContextRules),
	})
}

func (h *Handler) recordAdmin(r *http.Request, action, targetID string, status int, success bool, metadata any) {
	if h.adminAudit == nil {
		return
	}
	var actor *string
	if claims := auth.GetClaims(r.Context()); claims != nil {
		id := claims.UserID
		actor = &id
	}
	h.adminAudit.Record(r.Context(), adminaudit.Event{
		ActorUserID: actor,
		Action:      action,
		Resource:    "governance_policy",
		TargetID:    targetID,
		Path:        r.URL.Path,
		Method:      r.Method,
		StatusCode:  status,
		Success:     success,
		Metadata:    metadata,
	})
}

func policyToResp(p *Policy) policyResponse {
	updatedAt := ""
	if !p.UpdatedAt.IsZero() {
		updatedAt = p.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	rules := p.Rules
	if rules == nil {
		rules = []ProviderRule{}
	}
	roleRules := p.RoleRules
	if roleRules == nil {
		roleRules = []RoleRule{}
	}
	contextRules := p.ContextRules
	if contextRules == nil {
		contextRules = []ContextRule{}
	}
	return policyResponse{
		ID:           p.ID,
		Name:         p.Name,
		Mode:         p.Mode,
		Rules:        rules,
		RoleRules:    roleRules,
		ContextRules: contextRules,
		UpdatedAt:    updatedAt,
		UpdatedBy:    p.UpdatedBy,
		IsActive:     p.IsActive,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

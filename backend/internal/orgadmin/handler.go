//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// PR-T2.6: org management and SCIM token management HTTP handlers.
//
// Routes (all behind auth middleware):
//
//	GET    /api/orgs                            — global_admin: list all orgs
//	POST   /api/orgs                            — global_admin: create org
//	GET    /api/orgs/{org_id}                   — global_admin or own-org admin
//	PATCH  /api/orgs/{org_id}                   — global_admin or own-org admin
//	GET    /api/orgs/{org_id}/scim-tokens       — global_admin or own-org admin
//	POST   /api/orgs/{org_id}/scim-tokens       — global_admin or own-org admin
//	DELETE /api/orgs/{org_id}/scim-tokens/{id}  — global_admin or own-org admin

package orgadmin

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/domain"
)

// Handler serves org management and SCIM token management endpoints.
type Handler struct {
	repo       *Repository
	adminAudit adminaudit.Recorder
}

func NewHandler(repo *Repository, adminAudit adminaudit.Recorder) *Handler {
	return &Handler{repo: repo, adminAudit: adminAudit}
}

// ---------------------------------------------------------------------------
// GET /api/orgs — global_admin only
// ---------------------------------------------------------------------------

func (h *Handler) ListOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.repo.ListOrgs(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	if orgs == nil {
		orgs = []domain.Organization{}
	}
	writeJSON(w, http.StatusOK, orgs)
	h.record(r, "list", "organizations", "", nil)
}

// ---------------------------------------------------------------------------
// POST /api/orgs — global_admin only
// ---------------------------------------------------------------------------

func (h *Handler) CreateOrg(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.TrimSpace(req.Slug)
	if req.Name == "" || req.Slug == "" {
		writeErr(w, http.StatusBadRequest, "name and slug are required")
		return
	}

	org := &domain.Organization{
		ID:       uuid.NewString(),
		Name:     req.Name,
		Slug:     req.Slug,
		IsActive: true,
	}
	if err := h.repo.CreateOrg(r.Context(), org); err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			writeErr(w, http.StatusConflict, "slug already exists")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}

	writeJSON(w, http.StatusCreated, org)
	h.record(r, "create", "organization", org.ID, map[string]any{"slug": org.Slug})
}

// ---------------------------------------------------------------------------
// GET /api/orgs/{org_id}
// ---------------------------------------------------------------------------

func (h *Handler) GetOrg(w http.ResponseWriter, r *http.Request) {
	orgID := mux.Vars(r)["org_id"]
	org, err := h.repo.GetOrgByID(r.Context(), orgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "org not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, org)
	h.record(r, "read", "organization", orgID, nil)
}

// ---------------------------------------------------------------------------
// PATCH /api/orgs/{org_id}
// ---------------------------------------------------------------------------

func (h *Handler) UpdateOrg(w http.ResponseWriter, r *http.Request) {
	orgID := mux.Vars(r)["org_id"]

	existing, err := h.repo.GetOrgByID(r.Context(), orgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "org not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}

	var req struct {
		Name     *string `json:"name"`
		Slug     *string `json:"slug"`
		IsActive *bool   `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name != nil {
		existing.Name = strings.TrimSpace(*req.Name)
	}
	if req.Slug != nil {
		existing.Slug = strings.TrimSpace(*req.Slug)
	}
	if req.IsActive != nil {
		existing.IsActive = *req.IsActive
	}

	if err := h.repo.UpdateOrg(r.Context(), existing); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, existing)
	h.record(r, "update", "organization", orgID, map[string]any{"is_active": existing.IsActive})
}

// ---------------------------------------------------------------------------
// GET /api/orgs/{org_id}/scim-tokens
// ---------------------------------------------------------------------------

func (h *Handler) ListSCIMTokens(w http.ResponseWriter, r *http.Request) {
	orgID := mux.Vars(r)["org_id"]
	tokens, err := h.repo.ListSCIMTokens(r.Context(), orgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	if tokens == nil {
		tokens = []domain.SCIMToken{}
	}
	writeJSON(w, http.StatusOK, tokens)
	h.record(r, "list", "scim_tokens", orgID, nil)
}

// ---------------------------------------------------------------------------
// POST /api/orgs/{org_id}/scim-tokens
// Plaintext token returned once — never stored in DB.
// ---------------------------------------------------------------------------

func (h *Handler) CreateSCIMToken(w http.ResponseWriter, r *http.Request) {
	orgID := mux.Vars(r)["org_id"]

	// Verify org exists.
	if _, err := h.repo.GetOrgByID(r.Context(), orgID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "org not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}

	var req struct {
		Label string `json:"label"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	result, err := h.repo.CreateSCIMToken(r.Context(), orgID, strings.TrimSpace(req.Label))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}

	// Return token + plain value in one response — the only moment it's visible.
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":       result.Token,
		"plain_token": result.PlainToken, // operator must transmit to IdP and discard
		"warning":     "Store this token securely. It will not be shown again.",
	})
	h.record(r, "create", "scim_token", result.Token.ID, map[string]any{
		"org_id": orgID,
		"label":  result.Token.Label,
	})
}

// ---------------------------------------------------------------------------
// DELETE /api/orgs/{org_id}/scim-tokens/{token_id} — revoke (soft delete)
// ---------------------------------------------------------------------------

func (h *Handler) RevokeSCIMToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["org_id"]
	tokenID := vars["token_id"]

	if err := h.repo.RevokeSCIMToken(r.Context(), tokenID, orgID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "token not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}

	w.WriteHeader(http.StatusNoContent)
	h.record(r, "revoke", "scim_token", tokenID, map[string]any{"org_id": orgID})
}

// ---------------------------------------------------------------------------
// Audit helper
// ---------------------------------------------------------------------------

func (h *Handler) record(r *http.Request, action, resource, targetID string, metadata map[string]any) {
	if h.adminAudit == nil {
		return
	}
	claims := auth.GetClaims(r.Context())
	var actor *string
	var sourceOrg, targetOrg string
	if claims != nil {
		id := claims.UserID
		actor = &id
		sourceOrg = claims.OrgID
		// For cross-org operations, targetOrg is the org being acted upon.
		if tid := mux.Vars(r)["org_id"]; tid != "" && tid != claims.OrgID {
			targetOrg = tid
		}
	}

	meta := map[string]any{}
	for k, v := range metadata {
		meta[k] = v
	}
	if claims != nil && claims.BreakGlass {
		meta["break_glass"] = true
	}

	h.adminAudit.Record(r.Context(), adminaudit.Event{
		ActorUserID: actor,
		Action:      action,
		Resource:    resource,
		TargetID:    targetID,
		Path:        r.URL.Path,
		Method:      r.Method,
		StatusCode:  http.StatusOK,
		Success:     true,
		OrgID:       sourceOrg,
		SourceOrgID: sourceOrg,
		TargetOrgID: targetOrg,
		Metadata:    meta,
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

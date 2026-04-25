//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// PR-G4: org budget HTTP handlers.
//
// Routes (behind RequireOrgAccess middleware):
//   GET  /api/orgs/{org_id}/budget  — tenant admin or global_admin
//   PUT  /api/orgs/{org_id}/budget  — tenant admin or global_admin

package orgbudget

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/domain"
)

// Handler serves org budget management endpoints.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// GET /api/orgs/{org_id}/budget
func (h *Handler) GetBudget(w http.ResponseWriter, r *http.Request) {
	orgID := mux.Vars(r)["org_id"]
	status, err := h.svc.GetStatus(r.Context(), orgID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp{"internal"})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// PUT /api/orgs/{org_id}/budget
func (h *Handler) PutBudget(w http.ResponseWriter, r *http.Request) {
	orgID := mux.Vars(r)["org_id"]
	claims := auth.GetClaims(r.Context())

	// Verify org exists before attempting upsert — FK error would return 500 otherwise.
	if exists, err := h.svc.OrgExists(r.Context(), orgID); err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp{"internal"})
		return
	} else if !exists {
		writeJSON(w, http.StatusNotFound, errResp{"org not found"})
		return
	}

	var req struct {
		MonthlyLimitCents int64  `json:"monthly_limit_cents"`
		Mode              string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp{"invalid request body"})
		return
	}
	mode := domain.OrgBudgetPolicyMode(strings.TrimSpace(req.Mode))
	switch mode {
	case domain.OrgBudgetDisabled, domain.OrgBudgetObserve, domain.OrgBudgetEnforce:
	default:
		writeJSON(w, http.StatusBadRequest, errResp{"mode must be disabled|observe|enforce"})
		return
	}
	if req.MonthlyLimitCents < 0 {
		writeJSON(w, http.StatusBadRequest, errResp{"monthly_limit_cents must be >= 0"})
		return
	}

	var actorID, sourceOrgID string
	if claims != nil {
		actorID = claims.UserID
		sourceOrgID = claims.OrgID // may differ from orgID for global_admin cross-org ops
	}
	policy := &domain.OrgBudgetPolicy{
		OrgID:             orgID,
		MonthlyLimitCents: req.MonthlyLimitCents,
		Mode:              mode,
	}
	if err := h.svc.UpsertPolicy(r.Context(), policy, actorID, sourceOrgID); err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp{"internal"})
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type errResp struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

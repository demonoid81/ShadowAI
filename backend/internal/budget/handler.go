package budget

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/domain"
)

type UserOrgLookup interface {
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByIDScoped(ctx context.Context, id, orgID string) (*domain.User, error)
}

type Handler struct {
	svc        *Service
	userLookup UserOrgLookup
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) WithUserLookup(lookup UserOrgLookup) *Handler {
	h.userLookup = lookup
	return h
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["user_id"]
	if !h.authorizeTargetUser(w, r, userID) {
		return
	}
	b, err := h.svc.GetBudget(r.Context(), userID)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(b)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["user_id"]
	if !h.authorizeTargetUser(w, r, userID) {
		return
	}
	var b domain.Budget
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}
	b.UserID = userID
	if b.ID == "" {
		b.ID = uuid.New().String()
	}
	if err := h.svc.UpdateBudget(r.Context(), &b); err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(b)
}

func (h *Handler) authorizeTargetUser(w http.ResponseWriter, r *http.Request, userID string) bool {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return false
	}
	if userID == claims.UserID {
		return true
	}
	if !auth.IsPrivilegedAdminRole(claims.Role) && !claims.BreakGlass {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return false
	}
	orgID, global, err := auth.RequireOrg(claims)
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return false
	}
	if h.userLookup == nil {
		return true
	}
	if global {
		if _, err := h.userLookup.GetByID(r.Context(), userID); err != nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return false
		}
		return true
	}
	if _, err := h.userLookup.GetByIDScoped(r.Context(), userID, orgID); err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return false
	}
	return true
}

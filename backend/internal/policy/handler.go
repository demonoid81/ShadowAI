package policy

import (
	"encoding/json"
	"net/http"
	"github.com/gorilla/mux"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/domain"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	orgID, global, _ := auth.RequireOrg(claims)
	if global {
		orgID = ""
	}
	rules, err := h.svc.List(r.Context(), orgID)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	if rules == nil {
		rules = []domain.PolicyRule{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	orgID, global, _ := auth.RequireOrg(claims)
	if global {
		orgID = ""
	}
	var p domain.PolicyRule
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}
	p.OrgID = orgID
	if err := h.svc.Create(r.Context(), &p); err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(p)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	claims := auth.GetClaims(r.Context())
	orgID, global, _ := auth.RequireOrg(claims)
	if global {
		orgID = ""
	}
	var p domain.PolicyRule
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}
	p.ID = id
	p.OrgID = orgID
	if err := h.svc.Update(r.Context(), &p); err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	claims := auth.GetClaims(r.Context())
	orgID, global, _ := auth.RequireOrg(claims)
	if global {
		if err := h.svc.Delete(r.Context(), id); err != nil {
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
	} else {
		if err := h.svc.DeleteScoped(r.Context(), id, orgID); err != nil {
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

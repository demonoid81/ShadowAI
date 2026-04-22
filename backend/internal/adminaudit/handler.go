//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// Compiled only under -tags enterprise.

package adminaudit

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/shadowai/backend/internal/domain"
)

// Handler отдаёт GET /api/admin-events (admin-only, middleware-enforced).
type Handler struct {
	repo *Repository
}

func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

type listResponse struct {
	Data   []domain.AdminEvent `json:"data"`
	Total  int                 `json:"total"`
	Limit  int                 `json:"limit"`
	Offset int                 `json:"offset"`
}

// List обрабатывает GET /api/admin-events?actor_user_id=&resource=&action=&limit=&offset=.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	actorID := q.Get("actor_user_id")
	resource := q.Get("resource")
	action := q.Get("action")

	events, total, err := h.repo.List(r.Context(), limit, offset, actorID, resource, action)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []domain.AdminEvent{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(listResponse{
		Data: events, Total: total, Limit: limit, Offset: offset,
	})
}

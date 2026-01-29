package audit

import (
	"encoding/json"
	"net/http"
	"strconv"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

type listResponse struct {
	Data   []interface{} `json:"data"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	userID := r.URL.Query().Get("user_id")
	model := r.URL.Query().Get("model")
	policyAction := r.URL.Query().Get("policy_action")

	logs, total, err := h.svc.GetRepo().List(r.Context(), limit, offset, userID, model, policyAction)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	data := make([]interface{}, len(logs))
	for i, l := range logs {
		data[i] = l
	}
	if data == nil {
		data = []interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(listResponse{
		Data:   data,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

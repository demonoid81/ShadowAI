package audit

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

type Handler struct {
	svc           *Service
	payloadMode   PayloadMode
	retentionDays int
}

// NewHandler принимает также privacy-config. Если mode="" и
// retentionDays=0 — Status endpoint показывает их как есть (не
// ошибка, оператор видит "not configured").
func NewHandler(svc *Service, payloadMode PayloadMode, retentionDays int) *Handler {
	return &Handler{svc: svc, payloadMode: payloadMode, retentionDays: retentionDays}
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

	// has_shadow: валидируем whitelist'ом — любое другое значение → "any"
	// (fail-safe: misconfig в UI не должен ломать list, просто даёт default).
	hasShadow := r.URL.Query().Get("has_shadow")
	switch hasShadow {
	case "yes", "no":
		// OK
	default:
		hasShadow = ""
	}

	logs, total, err := h.svc.GetRepo().List(r.Context(), limit, offset, userID, model, policyAction, hasShadow)
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

// statusResponse — read-only view privacy/retention настроек + purge
// history для ops dashboard'ов. Не светит secrets.
type statusResponse struct {
	PayloadMode     string     `json:"payload_mode"`
	RetentionDays   int        `json:"retention_days"`
	LastPurgedAt    *time.Time `json:"last_purged_at,omitempty"`
	RowsPurgedTotal int        `json:"rows_purged_total"`
	SchedulerEnabled bool      `json:"scheduler_enabled"`
}

// Status отдаёт audit privacy config + purge history.
// Путь: GET /audit/status.
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	out := statusResponse{
		PayloadMode:   string(h.payloadMode),
		RetentionDays: h.retentionDays,
	}

	// SchedulerEnabled — true если retention сконфигурирован
	// (scheduler внутри main.go включается при interval>0 и retention>0,
	// но retention достаточный индикатор для UI).
	out.SchedulerEnabled = h.retentionDays > 0

	if repo := h.svc.GetRepo(); repo != nil {
		if last, err := repo.LastPurgeRun(r.Context()); err == nil && last != nil {
			out.LastPurgedAt = last.CompletedAt
		}
		if total, err := repo.TotalRowsPurged(r.Context()); err == nil {
			out.RowsPurgedTotal = total
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

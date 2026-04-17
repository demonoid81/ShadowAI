package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/auth"
)

type Handler struct {
	svc              *Service
	payloadMode      PayloadMode
	retentionDays    int
	schedulerEnabled bool
	// PR-D: admin-access audit. Nil — no-op (dev scenarios без БД).
	adminAudit adminaudit.Recorder
}

// NewHandler принимает также privacy-config и adminaudit.Recorder.
// Если mode="" и retentionDays=0 — Status endpoint показывает их как
// есть (не ошибка, оператор видит "not configured").
//
// schedulerEnabled — фактическое состояние embedded purge scheduler
// (caller считает `interval>0 && retention>0`).
func NewHandler(svc *Service, payloadMode PayloadMode, retentionDays int, schedulerEnabled bool, adminAudit adminaudit.Recorder) *Handler {
	return &Handler{
		svc:              svc,
		payloadMode:      payloadMode,
		retentionDays:    retentionDays,
		schedulerEnabled: schedulerEnabled,
		adminAudit:       adminAudit,
	}
}

// recordAdminRead — helper для унифицированной записи admin-read event'а
// из любого handler'а в этом пакете. claims может быть nil (в этом
// случае actor_user_id = NULL).
func (h *Handler) recordAdminRead(ctx context.Context, resource, path, method string, status int, metadata any) {
	if h.adminAudit == nil {
		return
	}
	var actor *string
	if c := auth.GetClaims(ctx); c != nil {
		id := c.UserID
		actor = &id
	}
	h.adminAudit.Record(ctx, adminaudit.Event{
		ActorUserID: actor,
		Action:      "read",
		Resource:    resource,
		Path:        path,
		Method:      method,
		StatusCode:  status,
		Success:     status < 400,
		Metadata:    metadata,
	})
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

	// PR-D: admin читает audit_logs — записываем факт чтения +
	// активные фильтры (без raw bodies — они и так не в filters).
	h.recordAdminRead(r.Context(), "audit_logs", r.URL.Path, r.Method, http.StatusOK, map[string]any{
		"user_id":       userID,
		"model":         model,
		"policy_action": policyAction,
		"has_shadow":    hasShadow,
		"limit":         limit,
		"offset":        offset,
		"total":         total,
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
		PayloadMode:      string(h.payloadMode),
		RetentionDays:    h.retentionDays,
		SchedulerEnabled: h.schedulerEnabled,
	}

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

	// PR-D: admin читает audit config/status — фиксируем.
	h.recordAdminRead(r.Context(), "audit_status", r.URL.Path, r.Method, http.StatusOK, nil)
}

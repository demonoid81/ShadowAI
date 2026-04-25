package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/auth"
)

// maskEmail — PR-D.1 privacy hardening. Screens admin UI/screenshots
// от утечки полного email. Сохраняет domain (для recognition) и
// первые 2 символа local part.
//
//	john.doe@example.com  → jo***@example.com
//	a@example.com         → *@example.com
//	""                     → ""
//	no-@-sign              → *** (маркер: не-email)
func maskEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		if email == "" {
			return ""
		}
		return "***"
	}
	local := email[:at]
	domain := email[at:]
	if len(local) <= 2 {
		return "*" + domain
	}
	return local[:2] + "***" + domain
}

type Handler struct {
	db         *sql.DB
	adminAudit adminaudit.Recorder
}

// NewHandler принимает optional adminaudit.Recorder (nil → no-op).
// Dashboard-endpoints — admin-only-reads, логируются как resource="dashboard".
func NewHandler(db *sql.DB, adminAudit adminaudit.Recorder) *Handler {
	return &Handler{db: db, adminAudit: adminAudit}
}

func (h *Handler) recordRead(ctx context.Context, path, method string, status int, metadata any) {
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
		Resource:    "dashboard",
		Path:        path,
		Method:      method,
		StatusCode:  status,
		Success:     status < 400,
		Metadata:    metadata,
	})
}

type Stats struct {
	TotalRequests   int     `json:"total_requests"`
	BlockedRequests int     `json:"blocked_requests"`
	TotalCost       float64 `json:"total_cost"`
	TotalTokens     int     `json:"total_tokens"`
	ActiveUsers     int     `json:"active_users"`
}

func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	orgID, global, _ := auth.RequireOrg(claims)
	if global {
		orgID = ""
	}

	var s Stats
	if orgID != "" {
		if err := h.db.QueryRowContext(r.Context(),
			`SELECT COUNT(*), COALESCE(SUM(CASE WHEN policy_action='blocked' THEN 1 ELSE 0 END),0),
			COALESCE(SUM(cost_usd),0), COALESCE(SUM(total_tokens),0)
			FROM audit_logs WHERE org_id = $1`, orgID).Scan(&s.TotalRequests, &s.BlockedRequests, &s.TotalCost, &s.TotalTokens); err != nil {
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
		if err := h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM users WHERE is_active=true AND org_id=$1`, orgID).Scan(&s.ActiveUsers); err != nil {
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
	} else {
		if err := h.db.QueryRowContext(r.Context(),
			`SELECT COUNT(*), COALESCE(SUM(CASE WHEN policy_action='blocked' THEN 1 ELSE 0 END),0),
			COALESCE(SUM(cost_usd),0), COALESCE(SUM(total_tokens),0)
			FROM audit_logs`).Scan(&s.TotalRequests, &s.BlockedRequests, &s.TotalCost, &s.TotalTokens); err != nil {
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
		if err := h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM users WHERE is_active=true`).Scan(&s.ActiveUsers); err != nil {
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
	h.recordRead(r.Context(), r.URL.Path, r.Method, http.StatusOK, map[string]any{
		"endpoint": "stats",
	})
}

type UsagePoint struct {
	Date     string  `json:"date"`
	Requests int     `json:"requests"`
	Cost     float64 `json:"cost"`
	Tokens   int     `json:"tokens"`
}

func (h *Handler) GetUsage(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	orgID, global, _ := auth.RequireOrg(claims)
	if global {
		orgID = ""
	}
	var rows *sql.Rows
	var err error
	if orgID != "" {
		rows, err = h.db.QueryContext(r.Context(),
			`SELECT created_at::date as day, COUNT(*), COALESCE(SUM(cost_usd),0), COALESCE(SUM(total_tokens),0)
			FROM audit_logs WHERE created_at > now() - interval '30 days' AND org_id = $1
			GROUP BY day ORDER BY day`, orgID)
	} else {
		rows, err = h.db.QueryContext(r.Context(),
			`SELECT created_at::date as day, COUNT(*), COALESCE(SUM(cost_usd),0), COALESCE(SUM(total_tokens),0)
			FROM audit_logs WHERE created_at > now() - interval '30 days'
			GROUP BY day ORDER BY day`)
	}
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var points []UsagePoint
	for rows.Next() {
		var p UsagePoint
		if err := rows.Scan(&p.Date, &p.Requests, &p.Cost, &p.Tokens); err != nil {
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	if points == nil {
		points = []UsagePoint{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(points)
	h.recordRead(r.Context(), r.URL.Path, r.Method, http.StatusOK, map[string]any{
		"endpoint":     "usage",
		"points_count": len(points),
	})
}

// TopUser — строка в /dashboard/top-users. PR-D.1: Email теперь
// masked — скриншоты админки не должны раскрывать PII клиентов.
// Primary identifier для lookup/UI — UserID. Полный email оператор
// получает через GET /api/users/{id} (аудируется в admin_event_logs).
type TopUser struct {
	UserID      string  `json:"user_id"`
	EmailMasked string  `json:"email_masked"`
	Requests    int     `json:"requests"`
	Cost        float64 `json:"cost"`
}

func (h *Handler) GetTopUsers(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	orgID, global, _ := auth.RequireOrg(claims)
	if global {
		orgID = ""
	}
	var rows *sql.Rows
	var err error
	if orgID != "" {
		rows, err = h.db.QueryContext(r.Context(),
			`SELECT a.user_id, u.email, COUNT(*), COALESCE(SUM(a.cost_usd),0)
			FROM audit_logs a JOIN users u ON a.user_id = u.id
			WHERE a.org_id = $1
			GROUP BY a.user_id, u.email ORDER BY SUM(a.cost_usd) DESC LIMIT 10`, orgID)
	} else {
		rows, err = h.db.QueryContext(r.Context(),
			`SELECT a.user_id, u.email, COUNT(*), COALESCE(SUM(a.cost_usd),0)
			FROM audit_logs a JOIN users u ON a.user_id = u.id
			GROUP BY a.user_id, u.email ORDER BY SUM(a.cost_usd) DESC LIMIT 10`)
	}
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var users []TopUser
	for rows.Next() {
		var u TopUser
		var rawEmail string
		if err := rows.Scan(&u.UserID, &rawEmail, &u.Requests, &u.Cost); err != nil {
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
		u.EmailMasked = maskEmail(rawEmail)
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	if users == nil {
		users = []TopUser{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
	h.recordRead(r.Context(), r.URL.Path, r.Method, http.StatusOK, map[string]any{
		"endpoint":    "top_users",
		"users_count": len(users),
	})
}

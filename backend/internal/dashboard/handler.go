package dashboard

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

type Handler struct {
	db *sql.DB
}

func NewHandler(db *sql.DB) *Handler {
	return &Handler{db: db}
}

type Stats struct {
	TotalRequests   int     `json:"total_requests"`
	BlockedRequests int     `json:"blocked_requests"`
	TotalCost       float64 `json:"total_cost"`
	TotalTokens     int     `json:"total_tokens"`
	ActiveUsers     int     `json:"active_users"`
}

func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	var s Stats
	h.db.QueryRowContext(r.Context(),
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN policy_action='blocked' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(cost_usd),0), COALESCE(SUM(total_tokens),0)
		FROM audit_logs`).Scan(&s.TotalRequests, &s.BlockedRequests, &s.TotalCost, &s.TotalTokens)

	h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM users WHERE is_active=true`).Scan(&s.ActiveUsers)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

type UsagePoint struct {
	Date     string  `json:"date"`
	Requests int     `json:"requests"`
	Cost     float64 `json:"cost"`
	Tokens   int     `json:"tokens"`
}

func (h *Handler) GetUsage(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(),
		`SELECT created_at::date as day, COUNT(*), COALESCE(SUM(cost_usd),0), COALESCE(SUM(total_tokens),0)
		FROM audit_logs WHERE created_at > now() - interval '30 days'
		GROUP BY day ORDER BY day`)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var points []UsagePoint
	for rows.Next() {
		var p UsagePoint
		rows.Scan(&p.Date, &p.Requests, &p.Cost, &p.Tokens)
		points = append(points, p)
	}
	if points == nil {
		points = []UsagePoint{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(points)
}

type TopUser struct {
	UserID   string  `json:"user_id"`
	Email    string  `json:"email"`
	Requests int     `json:"requests"`
	Cost     float64 `json:"cost"`
}

func (h *Handler) GetTopUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(),
		`SELECT a.user_id, u.email, COUNT(*), COALESCE(SUM(a.cost_usd),0)
		FROM audit_logs a JOIN users u ON a.user_id = u.id
		GROUP BY a.user_id, u.email ORDER BY SUM(a.cost_usd) DESC LIMIT 10`)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var users []TopUser
	for rows.Next() {
		var u TopUser
		rows.Scan(&u.UserID, &u.Email, &u.Requests, &u.Cost)
		users = append(users, u)
	}
	if users == nil {
		users = []TopUser{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

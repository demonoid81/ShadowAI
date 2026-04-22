package internaldb

import (
	"context"
	"encoding/json"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/pii"
)

type Handler struct {
	manager          *Manager
	repo             *Repository
	auditSvc         *audit.Service
	auditPayloadMode audit.PayloadMode
	dlpSvc           *dlp.Service
	// PR-D: admin access audit. CRUD sources → admin_event_logs
	// (больше не дублируется в audit_logs через writeAudit).
	adminAudit adminaudit.Recorder
}

// NewHandler принимает audit privacy-config (PR-A) и adminaudit.Recorder
// (PR-D). adminAudit=nil → CRUD admin operations не логируются
// (dev/tests).
func NewHandler(manager *Manager, repo *Repository, auditSvc *audit.Service, auditPayloadMode audit.PayloadMode, dlpSvc *dlp.Service, adminAudit adminaudit.Recorder) *Handler {
	return &Handler{
		manager:          manager,
		repo:             repo,
		auditSvc:         auditSvc,
		auditPayloadMode: auditPayloadMode,
		dlpSvc:           dlpSvc,
		adminAudit:       adminAudit,
	}
}

// writeAudit применяет AUDIT_PAYLOAD_MODE к raw bodies перед Insert.
// Единая точка privacy-enforcement для internaldb (аналог handler.auditLog
// в proxy). Пустой auditPayloadMode → fallback Full (backward compat для
// редких test-fixture'ов без полной настройки).
func (h *Handler) writeAudit(log *domain.AuditLog, piiFindings []pii.Finding) {
	if h.auditSvc == nil {
		return
	}
	mode := h.auditPayloadMode
	if mode == "" {
		mode = audit.PayloadModeFull
	}
	log.RequestBody, log.ResponseBody = audit.TransformBodies(
		mode, log.RequestBody, log.ResponseBody, h.dlpSvc, piiFindings)
	h.auditSvc.Log(log)
}

type sourceListResponse struct {
	Sources []string `json:"sources"`
}

type sourceAdminResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsActive    bool      `json:"is_active"`
	DSNMasked   string    `json:"dsn_masked"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type sourceCreateRequest struct {
	Name        string `json:"name"`
	DSN         string `json:"dsn"`
	Description string `json:"description"`
	IsActive    *bool  `json:"is_active"`
}

type sourceUpdateRequest struct {
	Name        *string `json:"name"`
	DSN         *string `json:"dsn"`
	Description *string `json:"description"`
	IsActive    *bool   `json:"is_active"`
}

type sourceTestResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	LatencyMs int    `json:"latency_ms"`
	Message    string `json:"message"`
}

type queryRequest struct {
	Source  string `json:"source"`
	Query   string `json:"query"`
	MaxRows int    `json:"max_rows"`
}

type queryResponse struct {
	Source     string                   `json:"source"`
	Columns    []string                 `json:"columns"`
	Rows       []map[string]interface{} `json:"rows"`
	RowCount   int                      `json:"row_count"`
	Truncated  bool                     `json:"truncated"`
	DurationMs int                      `json:"duration_ms"`
}

func (h *Handler) ListSources(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	sources := []string{}
	if h.manager != nil {
		sources = h.manager.ListSources()
	}

	h.writeJSON(w, http.StatusOK, sourceListResponse{Sources: sources})
	h.auditRequest(r.Context(), claims, "directory", "", "/api/internal-dbs", http.StatusOK, nil, time.Now())
}

func (h *Handler) ListManagedSources(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.repo == nil {
		h.writeError(w, http.StatusInternalServerError, "repository unavailable")
		return
	}

	sources, err := h.repo.ListSources(r.Context(), true)
	if err != nil {
		h.auditAdminRequest(r.Context(), claims, "list", "all", "/api/internal-dbs/sources", http.StatusInternalServerError, err, start)
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	resp := make([]sourceAdminResponse, 0, len(sources))
	for _, source := range sources {
		resp = append(resp, sourceAdminResponseFor(source))
	}
	h.auditAdminRequest(r.Context(), claims, "list", "all", "/api/internal-dbs/sources", http.StatusOK, nil, start)
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) GetSource(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.repo == nil {
		h.writeError(w, http.StatusInternalServerError, "repository unavailable")
		return
	}

	id, err := parseSourceID(mux.Vars(r)["id"])
	if err != nil {
		h.auditAdminRequest(r.Context(), claims, "get", "", "/api/internal-dbs/sources", http.StatusBadRequest, err, start)
		h.writeError(w, http.StatusBadRequest, "invalid source id")
		return
	}
	source, err := h.repo.GetByID(r.Context(), id)
	if err != nil {
		if isNotFoundError(err) {
			h.auditAdminRequest(r.Context(), claims, "get", id, "/api/internal-dbs/sources", http.StatusNotFound, err, start)
			h.writeError(w, http.StatusNotFound, "source not found")
			return
		}
		h.auditAdminRequest(r.Context(), claims, "get", id, "/api/internal-dbs/sources", http.StatusInternalServerError, err, start)
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	h.auditAdminRequest(r.Context(), claims, "get", id, "/api/internal-dbs/sources", http.StatusOK, nil, start, adminSourceIDPayload(source.ID))
	h.writeJSON(w, http.StatusOK, sourceAdminResponseFor(*source))
}

func (h *Handler) CreateSource(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.repo == nil {
		h.writeError(w, http.StatusInternalServerError, "repository unavailable")
		return
	}

	var req sourceCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.auditAdminRequest(r.Context(), claims, "create", "", "/api/internal-dbs/sources", http.StatusBadRequest, err, start)
		h.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	name, err := normalizeSourceName(req.Name)
	if err != nil {
		h.auditAdminRequest(r.Context(), claims, "create", "", "/api/internal-dbs/sources", http.StatusBadRequest, err, start)
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	dsn := strings.TrimSpace(req.DSN)
	if dsn == "" {
		h.auditAdminRequest(r.Context(), claims, "create", "", "/api/internal-dbs/sources", http.StatusBadRequest, errors.New("dsn is required"), start)
		h.writeError(w, http.StatusBadRequest, "dsn is required")
		return
	}
	if err := validateDSN(dsn); err != nil {
		h.auditAdminRequest(r.Context(), claims, "create", "", "/api/internal-dbs/sources", http.StatusBadRequest, err, start)
		h.writeError(w, http.StatusBadRequest, "invalid dsn")
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	source := &InternalDBSource{
		ID:          uuid.New().String(),
		Name:        name,
		DSN:         dsn,
		Description: strings.TrimSpace(req.Description),
		IsActive:    isActive,
	}

	if err := h.repo.Create(r.Context(), source, claims.UserID); err != nil {
		if isUniqueConstraintError(err) {
			h.auditAdminRequest(r.Context(), claims, "create", source.Name, "/api/internal-dbs/sources", http.StatusConflict, err, start)
			h.writeError(w, http.StatusConflict, "source already exists")
			return
		}
		h.auditAdminRequest(r.Context(), claims, "create", source.Name, "/api/internal-dbs/sources", http.StatusInternalServerError, err, start)
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := h.reloadManager(r.Context()); err != nil {
		h.auditAdminRequest(r.Context(), claims, "create", source.Name, "/api/internal-dbs/sources", http.StatusInternalServerError, err, start)
		h.writeError(w, http.StatusInternalServerError, "source created, but reload failed")
		return
	}

	created, err := h.repo.GetByID(r.Context(), source.ID)
	if err != nil {
		h.auditAdminRequest(r.Context(), claims, "create", source.Name, "/api/internal-dbs/sources", http.StatusInternalServerError, err, start)
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.auditAdminRequest(r.Context(), claims, "create", created.ID, "/api/internal-dbs/sources", http.StatusCreated, nil, start, adminSourceCreateAuditPayload(created))
	h.writeJSON(w, http.StatusCreated, sourceAdminResponseFor(*created))
}

func (h *Handler) UpdateSource(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.repo == nil {
		h.writeError(w, http.StatusInternalServerError, "repository unavailable")
		return
	}

	id, err := parseSourceID(mux.Vars(r)["id"])
	if err != nil {
		h.auditAdminRequest(r.Context(), claims, "update", "", "/api/internal-dbs/sources", http.StatusBadRequest, err, start)
		h.writeError(w, http.StatusBadRequest, "invalid source id")
		return
	}
	existing, err := h.repo.GetByID(r.Context(), id)
	if err != nil {
		if isNotFoundError(err) {
			h.auditAdminRequest(r.Context(), claims, "update", id, "/api/internal-dbs/sources", http.StatusNotFound, err, start)
			h.writeError(w, http.StatusNotFound, "source not found")
			return
		}
		h.auditAdminRequest(r.Context(), claims, "update", id, "/api/internal-dbs/sources", http.StatusInternalServerError, err, start)
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	var req sourceUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.auditAdminRequest(r.Context(), claims, "update", id, "/api/internal-dbs/sources", http.StatusBadRequest, err, start)
		h.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Name == nil && req.DSN == nil && req.Description == nil && req.IsActive == nil {
		h.auditAdminRequest(r.Context(), claims, "update", id, "/api/internal-dbs/sources", http.StatusBadRequest, errors.New("at least one field required"), start)
		h.writeError(w, http.StatusBadRequest, "at least one field required")
		return
	}

	if req.Name != nil {
		name, err := normalizeSourceName(*req.Name)
		if err != nil {
			h.auditAdminRequest(r.Context(), claims, "update", id, "/api/internal-dbs/sources", http.StatusBadRequest, err, start)
			h.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		existing.Name = name
	}
	if req.DSN != nil {
		dsn := strings.TrimSpace(*req.DSN)
		if dsn == "" {
			h.auditAdminRequest(r.Context(), claims, "update", id, "/api/internal-dbs/sources", http.StatusBadRequest, errors.New("dsn is required"), start)
			h.writeError(w, http.StatusBadRequest, "dsn is required")
			return
		}
		if err := validateDSN(dsn); err != nil {
			h.auditAdminRequest(r.Context(), claims, "update", id, "/api/internal-dbs/sources", http.StatusBadRequest, err, start)
			h.writeError(w, http.StatusBadRequest, "invalid dsn")
			return
		}
		existing.DSN = dsn
	}
	if req.Description != nil {
		existing.Description = strings.TrimSpace(*req.Description)
	}
	if req.IsActive != nil {
		existing.IsActive = *req.IsActive
	}

	if err := h.repo.Update(r.Context(), existing, claims.UserID); err != nil {
		if isUniqueConstraintError(err) {
			h.auditAdminRequest(r.Context(), claims, "update", existing.ID, "/api/internal-dbs/sources", http.StatusConflict, err, start)
			h.writeError(w, http.StatusConflict, "source already exists")
			return
		}
		if isNotFoundError(err) {
			h.auditAdminRequest(r.Context(), claims, "update", existing.ID, "/api/internal-dbs/sources", http.StatusNotFound, err, start)
			h.writeError(w, http.StatusNotFound, "source not found")
			return
		}
		h.auditAdminRequest(r.Context(), claims, "update", existing.ID, "/api/internal-dbs/sources", http.StatusInternalServerError, err, start)
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := h.reloadManager(r.Context()); err != nil {
		h.auditAdminRequest(r.Context(), claims, "update", existing.ID, "/api/internal-dbs/sources", http.StatusInternalServerError, err, start)
		h.writeError(w, http.StatusInternalServerError, "source updated, but reload failed")
		return
	}

	updated, err := h.repo.GetByID(r.Context(), existing.ID)
	if err != nil {
		h.auditAdminRequest(r.Context(), claims, "update", existing.ID, "/api/internal-dbs/sources", http.StatusInternalServerError, err, start)
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.auditAdminRequest(r.Context(), claims, "update", updated.ID, "/api/internal-dbs/sources", http.StatusOK, nil, start, adminSourceUpdateAuditPayload(updated, req))
	h.writeJSON(w, http.StatusOK, sourceAdminResponseFor(*updated))
}

func (h *Handler) DeleteSource(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.repo == nil {
		h.writeError(w, http.StatusInternalServerError, "repository unavailable")
		return
	}

	id, err := parseSourceID(mux.Vars(r)["id"])
	if err != nil {
		h.auditAdminRequest(r.Context(), claims, "delete", "", "/api/internal-dbs/sources", http.StatusBadRequest, err, start)
		h.writeError(w, http.StatusBadRequest, "invalid source id")
		return
	}
	if err := h.repo.Delete(r.Context(), id); err != nil {
		if isNotFoundError(err) {
			h.auditAdminRequest(r.Context(), claims, "delete", id, "/api/internal-dbs/sources", http.StatusNotFound, err, start)
			h.writeError(w, http.StatusNotFound, "source not found")
			return
		}
		h.auditAdminRequest(r.Context(), claims, "delete", id, "/api/internal-dbs/sources", http.StatusInternalServerError, err, start)
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if h.manager != nil {
		if err := h.reloadManager(r.Context()); err != nil {
			h.auditAdminRequest(r.Context(), claims, "delete", id, "/api/internal-dbs/sources", http.StatusInternalServerError, err, start)
			h.writeError(w, http.StatusInternalServerError, "source deleted, but reload failed")
			return
		}
	}
	h.auditAdminRequest(r.Context(), claims, "delete", id, "/api/internal-dbs/sources", http.StatusNoContent, nil, start)

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RefreshSources(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.manager == nil {
		h.writeError(w, http.StatusInternalServerError, "internal db manager unavailable")
		return
	}

	if err := h.manager.RefreshSources(r.Context()); err != nil {
		h.auditAdminRequest(r.Context(), claims, "refresh", "", "/api/internal-dbs/sources/refresh", http.StatusInternalServerError, err, start, marshalAuditPayload(map[string]interface{}{"action": "refresh"}))
		h.writeError(w, http.StatusInternalServerError, "refresh failed")
		return
	}

	h.auditAdminRequest(r.Context(), claims, "refresh", "all", "/api/internal-dbs/sources/refresh", http.StatusOK, nil, start, marshalAuditPayload(map[string]interface{}{"action": "refresh"}))
	h.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) TestSource(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.repo == nil {
		h.writeError(w, http.StatusInternalServerError, "repository unavailable")
		return
	}

	id, err := parseSourceID(mux.Vars(r)["id"])
	if err != nil {
		h.auditAdminRequest(r.Context(), claims, "test", "", "/api/internal-dbs/sources/{id}/test", http.StatusBadRequest, err, start)
		h.writeError(w, http.StatusBadRequest, "invalid source id")
		return
	}

	source, err := h.repo.GetByID(r.Context(), id)
	if err != nil {
		if isNotFoundError(err) {
			h.auditAdminRequest(r.Context(), claims, "test", id, "/api/internal-dbs/sources/{id}/test", http.StatusNotFound, err, start)
			h.writeError(w, http.StatusNotFound, "source not found")
			return
		}
		h.auditAdminRequest(r.Context(), claims, "test", id, "/api/internal-dbs/sources/{id}/test", http.StatusInternalServerError, err, start)
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	dsn := strings.TrimSpace(source.DSN)
	if dsn == "" {
		err := errors.New("dsn is required")
		h.auditAdminRequest(r.Context(), claims, "test", id, "/api/internal-dbs/sources/{id}/test", http.StatusBadRequest, err, start, adminSourceTestAuditPayload(source.ID, false, 0, source.Name))
		h.writeError(w, http.StatusBadRequest, "dsn is required")
		return
	}
	if err := validateDSN(dsn); err != nil {
		h.auditAdminRequest(r.Context(), claims, "test", id, "/api/internal-dbs/sources/{id}/test", http.StatusBadRequest, err, start, adminSourceTestAuditPayload(source.ID, false, 0, source.Name))
		h.writeError(w, http.StatusBadRequest, "invalid dsn")
		return
	}

	timeout := defaultQueryTimeout
	if h.manager != nil {
		timeout = h.manager.getQueryTimeout()
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		h.auditAdminRequest(r.Context(), claims, "test", id, "/api/internal-dbs/sources/{id}/test", http.StatusBadRequest, err, start, adminSourceTestAuditPayload(source.ID, false, 0, source.Name))
		h.writeError(w, http.StatusBadRequest, "invalid dsn")
		return
	}
	defer db.Close()

	var probe int
	if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&probe); err != nil {
		h.auditAdminRequest(r.Context(), claims, "test", id, "/api/internal-dbs/sources/{id}/test", http.StatusBadGateway, err, start, adminSourceTestAuditPayload(source.ID, false, int(time.Since(start).Milliseconds()), source.Name))
		h.writeError(w, http.StatusBadGateway, "source connectivity test failed")
		return
	}

	resp := sourceTestResponse{
		ID:         source.ID,
		Name:       source.Name,
		Status:     "ok",
		LatencyMs:  int(time.Since(start).Milliseconds()),
		Message:    "connection successful",
	}
	h.auditAdminRequest(r.Context(), claims, "test", id, "/api/internal-dbs/sources/{id}/test", http.StatusOK, nil, start, adminSourceTestAuditPayload(source.ID, true, resp.LatencyMs, source.Name))
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) Query(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		h.auditRequest(r.Context(), claims, "directory", "", "/api/internal-dbs/query", http.StatusUnauthorized, nil, start)
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.manager == nil {
		h.writeError(w, http.StatusInternalServerError, "internal db manager unavailable")
		return
	}

	var req queryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.auditRequest(r.Context(), claims, req.Source, "", "/api/internal-dbs/query", http.StatusBadRequest, ErrInvalidQuery, start)
		h.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Source = strings.ToLower(strings.TrimSpace(req.Source))
	req.Query = strings.TrimSpace(req.Query)

	if req.Source == "" {
		h.auditRequest(r.Context(), claims, req.Source, req.Query, "/api/internal-dbs/query", http.StatusBadRequest, ErrSourceNotFound, start)
		h.writeError(w, http.StatusBadRequest, "source is required")
		return
	}
	if req.Query == "" {
		h.auditRequest(r.Context(), claims, req.Source, req.Query, "/api/internal-dbs/query", http.StatusBadRequest, ErrInvalidQuery, start)
		h.writeError(w, http.StatusBadRequest, "query is required")
		return
	}
	if len(req.Query) > maxQueryLength {
		h.auditRequest(r.Context(), claims, req.Source, req.Query, "/api/internal-dbs/query", http.StatusBadRequest, ErrInvalidQuery, start)
		h.writeError(w, http.StatusBadRequest, "query is too long")
		return
	}

	columns, rows, truncated, err := h.manager.Query(r.Context(), req.Source, req.Query, req.MaxRows)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrNoSourcesConfigured) {
			status = http.StatusServiceUnavailable
		} else if errors.Is(err, ErrSourceNotFound) {
			status = http.StatusNotFound
		} else if errors.Is(err, ErrUnsupportedSQL) {
			status = http.StatusUnprocessableEntity
		} else {
			status = http.StatusBadGateway
		}

		h.auditRequest(r.Context(), claims, req.Source, req.Query, "/api/internal-dbs/query", status, err, start)
		h.writeError(w, status, err.Error())
		return
	}

	response := queryResponse{
		Source:     req.Source,
		Columns:    columns,
		Rows:       rows,
		RowCount:   len(rows),
		Truncated:  truncated,
		DurationMs: int(time.Since(start).Milliseconds()),
	}

	h.auditRequest(r.Context(), claims, req.Source, req.Query, "/api/internal-dbs/query", http.StatusOK, nil, start)
	h.writeJSON(w, http.StatusOK, response)
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sql.ErrNoRows) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *Handler) writeError(w http.ResponseWriter, status int, msg string) {
	h.writeJSON(w, status, map[string]string{"error": msg})
}

func (h *Handler) auditRequest(ctx context.Context, claims *auth.Claims, source, query, endpoint string, status int, err error, start time.Time) {
	if h == nil || h.auditSvc == nil || claims == nil {
		return
	}

	findings := pii.Scan(query)
	policyAction := "allowed"
	if err != nil {
		policyAction = "blocked"
	}

	req := auditRequestPayload(query)

	h.writeAudit(&domain.AuditLog{
		ID:           uuid.New().String(),
		UserID:       claims.UserID,
		RequestBody:  req,
		Model:        "internal-db",
		Provider:     source,
		Endpoint:     endpoint,
		StatusCode:   status,
		PIIDetected:  len(findings) > 0,
		PIITypes:     pii.DetectedTypes(findings),
		PolicyAction: policyAction,
		DurationMs:   int(time.Since(start).Milliseconds()),
	}, findings)
}

func (h *Handler) reloadManager(ctx context.Context) error {
	if h == nil || h.manager == nil {
		return nil
	}
	return h.manager.RefreshSources(ctx)
}

// auditAdminRequest — PR-D: переключён с audit_logs на admin_event_logs.
// Admin CRUD над internal-db sources это control-plane действие,
// а не user LLM-traffic. Сохраняем minimal-safe metadata: operation,
// source, pii_detected — без raw payload (DSN/query может содержать
// secrets). rawPayload теперь игнорируется: мы только отмечаем факт
// попытки, а содержимое — не в scope admin event logs.
func (h *Handler) auditAdminRequest(ctx context.Context, claims *auth.Claims, operation, source, endpoint string, status int, err error, start time.Time, rawPayload ...string) {
	if h == nil || h.adminAudit == nil || claims == nil {
		return
	}

	var piiDetected bool
	if len(rawPayload) > 0 {
		piiDetected = len(pii.Scan(rawPayload[0])) > 0
	}

	method := "CONTROL"
	resource := "internal_db_source"
	action := operation

	metadata := map[string]any{
		"source":       source,
		"operation":    operation,
		"pii_detected": piiDetected,
		"duration_ms":  int(time.Since(start).Milliseconds()),
	}
	if err != nil {
		metadata["error"] = err.Error()
	}

	actor := &claims.UserID
	h.adminAudit.Record(ctx, adminaudit.Event{
		ActorUserID: actor,
		Action:      action,
		Resource:    resource,
		TargetID:    source,
		Path:        endpoint,
		Method:      method,
		StatusCode:  status,
		Success:     err == nil && status < 400,
		Metadata:    metadata,
	})
}

func auditRequestPayload(raw string) string {
	if raw == "" {
		return ""
	}
	redacted := raw
	for _, p := range pii.Patterns {
		redacted = p.Pattern.ReplaceAllString(redacted, "[redacted:"+p.Name+"]")
	}
	if len(redacted) > 2000 {
		return redacted[:2000] + "..."
	}
	return redacted
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}

func maskDSN(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid-dsn]"
	}
	if u.User != nil {
		u.User = url.UserPassword("***", "***")
	}
	return u.String()
}

func adminSourceCreateAuditPayload(source *InternalDBSource) string {
	return marshalAuditPayload(map[string]interface{}{
		"id":          source.ID,
		"name":        source.Name,
		"dsn_masked":  maskDSN(source.DSN),
		"description": source.Description,
		"is_active":   source.IsActive,
	})
}

func adminSourceUpdateAuditPayload(source *InternalDBSource, req sourceUpdateRequest) string {
	payload := map[string]interface{}{
		"id": source.ID,
	}
	if req.Name != nil {
		payload["name"] = source.Name
	}
	if req.DSN != nil {
		payload["dsn_masked"] = maskDSN(source.DSN)
	}
	if req.Description != nil {
		payload["description"] = source.Description
	}
	if req.IsActive != nil {
		payload["is_active"] = source.IsActive
	}
	return marshalAuditPayload(payload)
}

func adminSourceTestAuditPayload(sourceID string, connected bool, latencyMs int, name string) string {
	return marshalAuditPayload(map[string]interface{}{
		"id":          sourceID,
		"name":        name,
		"connected":   connected,
		"latency_ms":  latencyMs,
	})
}

func adminSourceIDPayload(id string) string {
	return marshalAuditPayload(map[string]interface{}{
		"id": id,
	})
}

func marshalAuditPayload(payload map[string]interface{}) string {
	out, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(out)
}

func sourceAdminResponseFor(source InternalDBSource) sourceAdminResponse {
	return sourceAdminResponse{
		ID:          source.ID,
		Name:        source.Name,
		Description: source.Description,
		IsActive:    source.IsActive,
		DSNMasked:   maskDSN(source.DSN),
		CreatedAt:   source.CreatedAt,
		UpdatedAt:   source.UpdatedAt,
	}
}

func parseSourceID(raw string) (string, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid source id")
	}
	return id.String(), nil
}

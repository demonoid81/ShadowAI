//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package legalhold

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/auth"
)

// caseRefHash — PR-L1.1: не пишем raw case_ref в admin_event_logs
// (→ SIEM mirror). Вместо этого truncated SHA-256 для SIEM-side
// correlation ("все события для case с hash X"). 16 hex = 64 bit,
// коллизии крайне редкие. Raw case_ref остаётся в legal_holds
// table для legal audit (доступен только admin через GET
// /api/legal-holds).
func caseRefHash(caseRef string) string {
	sum := sha256.Sum256([]byte(caseRef))
	return hex.EncodeToString(sum[:8])
}

// Handler обслуживает admin-only CRUD для legal holds.
//
// Routes:
//
//	POST /api/legal-holds             — apply hold
//	POST /api/legal-holds/{id}/release — release
//	GET  /api/legal-holds              — list active + history
//
// Все ответы регистрируются в admin_event_logs (resource=legal_hold).
type Handler struct {
	svc        *Service
	adminAudit adminaudit.Recorder
}

func NewHandler(svc *Service, adminAudit adminaudit.Recorder) *Handler {
	return &Handler{svc: svc, adminAudit: adminAudit}
}

type createRequest struct {
	TargetUserID string `json:"target_user_id"`
	CaseRef      string `json:"case_ref"`
	Reason       string `json:"reason"`
}

type holdResponse struct {
	ID           string  `json:"id"`
	TargetUserID string  `json:"target_user_id"`
	CaseRef      string  `json:"case_ref"`
	Reason       string  `json:"reason"`
	CreatedBy    *string `json:"created_by,omitempty"`
	CreatedAt    string  `json:"created_at"`
	ReleasedAt   *string `json:"released_at,omitempty"`
	ReleasedBy   *string `json:"released_by,omitempty"`
	IsActive     bool    `json:"is_active"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// Create — POST /api/legal-holds. Admin-only. Body:
// {"target_user_id":..., "case_ref":..., "reason":...}
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	if claims.Role != auth.RoleAdmin {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: "forbidden"})
		return
	}

	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		h.recordAdmin(r, "apply_hold", "", http.StatusBadRequest, false, map[string]any{"error": "invalid_json"})
		return
	}

	hold, err := h.svc.CreateHold(r.Context(), req.TargetUserID, req.CaseRef, req.Reason, claims.UserID)
	if err != nil {
		// PR-L1.1: split error paths. Validation → 400 (generic);
		// not configured → 503; already active → 409; всё остальное
		// (repo/runtime) → 500 generic. Raw err.Error() НЕ уходит
		// клиенту; admin audit получает machine-readable error_code.
		switch {
		case IsAlreadyActive(err):
			writeJSON(w, http.StatusConflict, errorResponse{Error: "user already has active hold"})
			h.recordAdmin(r, "apply_hold", req.TargetUserID, http.StatusConflict, false, map[string]any{
				"error_code":     "already_active",
				"case_ref_hash":  caseRefHash(req.CaseRef),
			})
		case IsValidation(err):
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request"})
			h.recordAdmin(r, "apply_hold", req.TargetUserID, http.StatusBadRequest, false, map[string]any{
				"error_code": "validation_failed",
			})
		case IsNotConfigured(err):
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "legal hold not configured"})
			h.recordAdmin(r, "apply_hold", req.TargetUserID, http.StatusServiceUnavailable, false, map[string]any{
				"error_code": "not_configured",
			})
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "hold creation failed"})
			h.recordAdmin(r, "apply_hold", req.TargetUserID, http.StatusInternalServerError, false, map[string]any{
				"error_code": "internal_error",
			})
		}
		return
	}

	writeJSON(w, http.StatusCreated, toResponse(hold))
	// PR-L1.1: case_ref_hash вместо raw case_ref в metadata. Raw
	// остаётся в legal_holds table (доступен через GET), но не
	// дублируется в admin_event_logs / SIEM.
	h.recordAdmin(r, "apply_hold", hold.ID, http.StatusCreated, true, map[string]any{
		"target_user_id": hold.TargetUserID,
		"case_ref_hash":  caseRefHash(hold.CaseRef),
	})
}

// Release — POST /api/legal-holds/{id}/release. Admin-only. Body не
// требуется.
func (h *Handler) Release(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	if claims.Role != auth.RoleAdmin {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: "forbidden"})
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "missing id"})
		return
	}

	hold, err := h.svc.ReleaseHold(r.Context(), id, claims.UserID)
	if err != nil {
		// PR-L1.1: machine-readable error_code в metadata.
		switch {
		case IsNotFound(err):
			writeJSON(w, http.StatusNotFound, errorResponse{Error: "hold not found"})
			h.recordAdmin(r, "release_hold", id, http.StatusNotFound, false, map[string]any{
				"error_code": "not_found",
			})
		case IsNotActive(err):
			// Идемпотентность: already-released — 200 с маркером.
			writeJSON(w, http.StatusOK, map[string]any{
				"id":     id,
				"status": "already_released",
			})
			h.recordAdmin(r, "release_hold", id, http.StatusOK, true, map[string]any{
				"status": "already_released",
			})
		case IsValidation(err):
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request"})
			h.recordAdmin(r, "release_hold", id, http.StatusBadRequest, false, map[string]any{
				"error_code": "validation_failed",
			})
		case IsNotConfigured(err):
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "legal hold not configured"})
			h.recordAdmin(r, "release_hold", id, http.StatusServiceUnavailable, false, map[string]any{
				"error_code": "not_configured",
			})
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "hold release failed"})
			h.recordAdmin(r, "release_hold", id, http.StatusInternalServerError, false, map[string]any{
				"error_code": "internal_error",
			})
		}
		return
	}

	writeJSON(w, http.StatusOK, toResponse(hold))
	// PR-L1.1: case_ref_hash вместо raw case_ref.
	h.recordAdmin(r, "release_hold", hold.ID, http.StatusOK, true, map[string]any{
		"target_user_id": hold.TargetUserID,
		"case_ref_hash":  caseRefHash(hold.CaseRef),
	})
}

// List — GET /api/legal-holds. Admin-only. Возвращает все holds
// (active + released) в порядке active-first, created_at DESC.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	if claims.Role != auth.RoleAdmin {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: "forbidden"})
		return
	}

	holds, err := h.svc.List(r.Context())
	if err != nil {
		if IsNotConfigured(err) {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "legal hold not configured"})
			h.recordAdmin(r, "read", "", http.StatusServiceUnavailable, false, map[string]any{
				"error_code": "not_configured",
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal"})
		h.recordAdmin(r, "read", "", http.StatusInternalServerError, false, map[string]any{
			"error_code": "internal_error",
		})
		return
	}
	out := make([]holdResponse, 0, len(holds))
	activeCount := 0
	for i := range holds {
		out = append(out, toResponse(&holds[i]))
		if holds[i].IsActive {
			activeCount++
		}
	}
	writeJSON(w, http.StatusOK, out)
	h.recordAdmin(r, "read", "", http.StatusOK, true, map[string]any{
		"resource_subtype": "legal_hold_list",
		"total":            len(holds),
		"active_count":     activeCount,
	})
}

func (h *Handler) recordAdmin(r *http.Request, action, targetID string, status int, success bool, metadata any) {
	if h.adminAudit == nil {
		return
	}
	var actor *string
	if claims := auth.GetClaims(r.Context()); claims != nil {
		id := claims.UserID
		actor = &id
	}
	h.adminAudit.Record(r.Context(), adminaudit.Event{
		ActorUserID: actor,
		Action:      action,
		Resource:    "legal_hold",
		TargetID:    targetID,
		Path:        r.URL.Path,
		Method:      r.Method,
		StatusCode:  status,
		Success:     success,
		Metadata:    metadata,
	})
}

func toResponse(h *Hold) holdResponse {
	r := holdResponse{
		ID:           h.ID,
		TargetUserID: h.TargetUserID,
		CaseRef:      h.CaseRef,
		Reason:       h.Reason,
		CreatedBy:    h.CreatedBy,
		CreatedAt:    h.CreatedAt.UTC().Format(time.RFC3339),
		IsActive:     h.IsActive,
	}
	if h.ReleasedAt != nil {
		s := h.ReleasedAt.UTC().Format(time.RFC3339)
		r.ReleasedAt = &s
	}
	if h.ReleasedBy != nil {
		r.ReleasedBy = h.ReleasedBy
	}
	return r
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

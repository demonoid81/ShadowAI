//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package legalhold

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/auth"
)

// tokenizer — PR-L1.2: keyed HMAC-SHA256 (truncated к 16 hex =
// 64 bit) вместо plain SHA-256 для case_ref-токена в SIEM/admin
// metadata. Keyed tokenizer предотвращает offline brute-force
// guessable case ID форматов (SEC-2026-NNN и т.п.). Secret задан в
// LEGAL_HOLD_TOKEN_SECRET; prod-валидация в validate_enterprise.go
// требует >=32 chars (только enterprise build).
//
// Fallback: если secret пустой (dev/legacy deploy), Tokenize()
// возвращает unkeyed SHA-256 hash + логирует WARNING один раз на
// process. Warning emission защищён sync.Once — безопасно при
// concurrent requests (PR-L1.3 data-race fix).
type tokenizer struct {
	secret    []byte
	warnOnce  sync.Once
}

// newTokenizer. Пустой secret → unkeyed mode (dev only — prod
// startup-guard в enterprise build отвергает).
func newTokenizer(secret string) *tokenizer {
	return &tokenizer{secret: []byte(secret)}
}

// Tokenize возвращает 16-hex-char токен case_ref. Деterministic
// относительно secret: одинаковый (secret, caseRef) → одинаковый
// token (SIEM correlation сохраняется). Безопасно вызывать
// concurrently.
func (t *tokenizer) Tokenize(caseRef string) string {
	if len(t.secret) == 0 {
		// Unkeyed fallback — для dev / legacy без secret.
		// sync.Once гарантирует один warning per-process
		// независимо от concurrent Tokenize-вызовов.
		t.warnOnce.Do(func() {
			log.Printf("legalhold: LEGAL_HOLD_TOKEN_SECRET not set, using unkeyed SHA-256 for case_ref tokens — DEV ONLY, brute-force-weak")
		})
		sum := sha256.Sum256([]byte(caseRef))
		return hex.EncodeToString(sum[:8])
	}
	mac := hmac.New(sha256.New, t.secret)
	mac.Write([]byte(caseRef))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// Handler обслуживает admin-only CRUD для legal holds.
//
// Routes (PR-L2.3 — 4-eyes workflow):
//
//	POST /api/legal-holds              — создать pending hold
//	POST /api/legal-holds/{id}/approve — pending → active (4-eyes)
//	POST /api/legal-holds/{id}/reject  — pending → released (cancel)
//	POST /api/legal-holds/{id}/release — active → released (normal)
//	GET  /api/legal-holds              — list (active+pending+released)
//
// 4-eyes policy: approver должен отличаться от creator. Violation
// → 403 apply_hold_self_approval. Hold effective (блокирует DSAR и
// защищает от purge) ТОЛЬКО после approve.
//
// Admin events:
//
//	apply_hold_requested — create (pending)
//	apply_hold_approved  — approve (pending → active)
//	apply_hold_rejected  — reject (pending → released)
//	release_hold         — release (active → released)
//	read                 — list
//
// Все ответы регистрируются в admin_event_logs (resource=legal_hold).
type Handler struct {
	svc        *Service
	adminAudit adminaudit.Recorder
	tokens     *tokenizer
}

// NewHandler — каноничный конструктор. Использует unkeyed tokenizer
// (совместимость с существующими тестами). Для prod wiring
// передавайте secret через NewHandlerWithSecret.
func NewHandler(svc *Service, adminAudit adminaudit.Recorder) *Handler {
	return &Handler{svc: svc, adminAudit: adminAudit, tokens: newTokenizer("")}
}

// NewHandlerWithSecret — PR-L1.2: конструктор с LEGAL_HOLD_TOKEN_SECRET
// для keyed-HMAC case_ref токенов в admin_event_logs / SIEM mirror.
// Prod wiring (enterprise_wire.go) должен использовать именно этот
// вариант.
func NewHandlerWithSecret(svc *Service, adminAudit adminaudit.Recorder, tokenSecret string) *Handler {
	return &Handler{svc: svc, adminAudit: adminAudit, tokens: newTokenizer(tokenSecret)}
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
	Status       string  `json:"status"`
	CreatedBy    *string `json:"created_by,omitempty"`
	CreatedAt    string  `json:"created_at"`
	ApprovedAt   *string `json:"approved_at,omitempty"`
	ApprovedBy   *string `json:"approved_by,omitempty"`
	ReleasedAt   *string `json:"released_at,omitempty"`
	ReleasedBy   *string `json:"released_by,omitempty"`
	IsActive     bool    `json:"is_active"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// Create — POST /api/legal-holds. Admin-only. Body:
// {"target_user_id":..., "case_ref":..., "reason":...}
//
// PR-L2.3: hold создаётся в status='pending', НЕ блокирует DSAR
// и НЕ защищает от purge до approve. Admin event action —
// "apply_hold_requested" (раньше был "apply_hold" — breaking
// change для SIEM-consumer'ов; changelog 1.17 документирует).
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
		h.recordAdmin(r, "apply_hold_requested", "", http.StatusBadRequest, false, map[string]any{"error": "invalid_json"})
		return
	}

	hold, err := h.svc.CreateHold(r.Context(), req.TargetUserID, req.CaseRef, req.Reason, claims.UserID)
	if err != nil {
		// PR-L1.1: split error paths. Validation → 400 (generic);
		// not configured → 503; already active/pending → 409; всё
		// остальное (repo/runtime) → 500 generic. Raw err.Error() НЕ
		// уходит клиенту; admin audit получает machine-readable
		// error_code.
		switch {
		case IsAlreadyActive(err):
			// L2.3: "already active" теперь означает "уже есть
			// blocking (pending или active) hold для user'а" —
			// partial-unique index покрывает оба статуса.
			writeJSON(w, http.StatusConflict, errorResponse{Error: "user already has blocking hold"})
			h.recordAdmin(r, "apply_hold_requested", req.TargetUserID, http.StatusConflict, false, map[string]any{
				"error_code":    "already_blocking",
				"case_ref_hash": h.tokens.Tokenize(req.CaseRef),
			})
		case IsValidation(err):
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request"})
			h.recordAdmin(r, "apply_hold_requested", req.TargetUserID, http.StatusBadRequest, false, map[string]any{
				"error_code": "validation_failed",
			})
		case IsNotConfigured(err):
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "legal hold not configured"})
			h.recordAdmin(r, "apply_hold_requested", req.TargetUserID, http.StatusServiceUnavailable, false, map[string]any{
				"error_code": "not_configured",
			})
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "hold creation failed"})
			h.recordAdmin(r, "apply_hold_requested", req.TargetUserID, http.StatusInternalServerError, false, map[string]any{
				"error_code": "internal_error",
			})
		}
		return
	}

	writeJSON(w, http.StatusCreated, toResponse(hold))
	// PR-L1.1: case_ref_hash вместо raw case_ref. PR-L2.3: status
	// в metadata для SIEM-фильтров ("created pending" vs old
	// "immediately active").
	h.recordAdmin(r, "apply_hold_requested", hold.ID, http.StatusCreated, true, map[string]any{
		"target_user_id": hold.TargetUserID,
		"case_ref_hash":  h.tokens.Tokenize(hold.CaseRef),
		"status":         string(hold.Status),
	})
}

// Approve — POST /api/legal-holds/{id}/approve. Admin-only. Body
// не требуется. 4-eyes policy: approver должен отличаться от
// creator, иначе 403 + admin event apply_hold_self_approval.
//
// Semantics:
//
//	pending   → active  (200, apply_hold_approved success=true)
//	active    → 409     (already_active, action=apply_hold_approved)
//	released  → 409     (already_released)
//	not found → 404
//	self      → 403     (metadata.error_code="self_approval")
func (h *Handler) Approve(w http.ResponseWriter, r *http.Request) {
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

	hold, err := h.svc.Approve(r.Context(), id, claims.UserID)
	if err != nil {
		switch {
		case IsNotFound(err):
			writeJSON(w, http.StatusNotFound, errorResponse{Error: "hold not found"})
			h.recordAdmin(r, "apply_hold_approved", id, http.StatusNotFound, false, map[string]any{
				"error_code": "not_found",
			})
		case IsSelfApproval(err):
			// 4-eyes violation. 403 + отдельный event_code для
			// SIEM-alerting (это подозрительная активность —
			// admin пытается apply + approve собственный hold).
			writeJSON(w, http.StatusForbidden, errorResponse{Error: "approver must differ from creator"})
			h.recordAdmin(r, "apply_hold_approved", id, http.StatusForbidden, false, map[string]any{
				"error_code": "self_approval",
			})
		case IsNotPending(err):
			writeJSON(w, http.StatusConflict, errorResponse{Error: "hold is not pending"})
			h.recordAdmin(r, "apply_hold_approved", id, http.StatusConflict, false, map[string]any{
				"error_code": "not_pending",
			})
		case IsValidation(err):
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request"})
			h.recordAdmin(r, "apply_hold_approved", id, http.StatusBadRequest, false, map[string]any{
				"error_code": "validation_failed",
			})
		case IsNotConfigured(err):
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "legal hold not configured"})
			h.recordAdmin(r, "apply_hold_approved", id, http.StatusServiceUnavailable, false, map[string]any{
				"error_code": "not_configured",
			})
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "hold approval failed"})
			h.recordAdmin(r, "apply_hold_approved", id, http.StatusInternalServerError, false, map[string]any{
				"error_code": "internal_error",
			})
		}
		return
	}

	writeJSON(w, http.StatusOK, toResponse(hold))
	h.recordAdmin(r, "apply_hold_approved", hold.ID, http.StatusOK, true, map[string]any{
		"target_user_id": hold.TargetUserID,
		"case_ref_hash":  h.tokens.Tokenize(hold.CaseRef),
		"status":         string(hold.Status),
	})
}

// Reject — POST /api/legal-holds/{id}/reject. Admin-only. Body не
// требуется. pending → released (rejected / cancelled). Отличается
// от Release: Release работает на active, Reject — на pending.
// Rejector может быть тем же admin, что и creator (это cancellation
// собственного request'а, не approval).
func (h *Handler) Reject(w http.ResponseWriter, r *http.Request) {
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

	hold, err := h.svc.Reject(r.Context(), id, claims.UserID)
	if err != nil {
		switch {
		case IsNotFound(err):
			writeJSON(w, http.StatusNotFound, errorResponse{Error: "hold not found"})
			h.recordAdmin(r, "apply_hold_rejected", id, http.StatusNotFound, false, map[string]any{
				"error_code": "not_found",
			})
		case IsNotPending(err):
			writeJSON(w, http.StatusConflict, errorResponse{Error: "hold is not pending"})
			h.recordAdmin(r, "apply_hold_rejected", id, http.StatusConflict, false, map[string]any{
				"error_code": "not_pending",
			})
		case IsValidation(err):
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request"})
			h.recordAdmin(r, "apply_hold_rejected", id, http.StatusBadRequest, false, map[string]any{
				"error_code": "validation_failed",
			})
		case IsNotConfigured(err):
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "legal hold not configured"})
			h.recordAdmin(r, "apply_hold_rejected", id, http.StatusServiceUnavailable, false, map[string]any{
				"error_code": "not_configured",
			})
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "hold rejection failed"})
			h.recordAdmin(r, "apply_hold_rejected", id, http.StatusInternalServerError, false, map[string]any{
				"error_code": "internal_error",
			})
		}
		return
	}

	writeJSON(w, http.StatusOK, toResponse(hold))
	h.recordAdmin(r, "apply_hold_rejected", hold.ID, http.StatusOK, true, map[string]any{
		"target_user_id": hold.TargetUserID,
		"case_ref_hash":  h.tokens.Tokenize(hold.CaseRef),
		"status":         string(hold.Status),
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
		case IsPendingNotReleasable(err):
			// PR-L2.3: pending hold нельзя release. Operator должен
			// использовать /reject. Возвращаем 409, НЕ 200
			// already_released — контракт "pending ещё не был active"
			// требует явной отмены через другой endpoint.
			writeJSON(w, http.StatusConflict, errorResponse{Error: "hold is pending, use reject to cancel"})
			h.recordAdmin(r, "release_hold", id, http.StatusConflict, false, map[string]any{
				"error_code": "pending_not_releasable",
			})
		case IsNotActive(err):
			// Идемпотентность: already-released (ранее был active →
			// released). 200 с маркером.
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
		"case_ref_hash":  h.tokens.Tokenize(hold.CaseRef),
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
	pendingCount := 0
	for i := range holds {
		out = append(out, toResponse(&holds[i]))
		switch holds[i].Status {
		case StatusActive:
			activeCount++
		case StatusPending:
			pendingCount++
		}
	}
	writeJSON(w, http.StatusOK, out)
	h.recordAdmin(r, "read", "", http.StatusOK, true, map[string]any{
		"resource_subtype": "legal_hold_list",
		"total":            len(holds),
		"active_count":     activeCount,
		"pending_count":    pendingCount,
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
		Status:       string(h.Status),
		CreatedBy:    h.CreatedBy,
		CreatedAt:    h.CreatedAt.UTC().Format(time.RFC3339),
		IsActive:     h.IsActive,
	}
	if h.ApprovedAt != nil {
		s := h.ApprovedAt.UTC().Format(time.RFC3339)
		r.ApprovedAt = &s
	}
	if h.ApprovedBy != nil {
		r.ApprovedBy = h.ApprovedBy
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

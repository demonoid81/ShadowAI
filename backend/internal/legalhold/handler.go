//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package legalhold

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/domain"
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
	secret   []byte
	warnOnce sync.Once
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
	userLookup UserOrgLookup
}

type UserOrgLookup interface {
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByIDScoped(ctx context.Context, id, orgID string) (*domain.User, error)
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

func (h *Handler) WithUserLookup(lookup UserOrgLookup) *Handler {
	h.userLookup = lookup
	return h
}

func requirePrivilegedAdmin(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return nil, false
	}
	if !auth.IsPrivilegedAdminRole(claims.Role) && !claims.BreakGlass {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: "forbidden"})
		return nil, false
	}
	return claims, true
}

func (h *Handler) orgScopeForClaims(claims *auth.Claims) (string, bool) {
	orgID, global, err := auth.RequireOrg(claims)
	if err != nil {
		return "", false
	}
	if global {
		return "", true
	}
	return orgID, true
}

func (h *Handler) resolveTargetOrg(ctx context.Context, targetUserID string, claims *auth.Claims) (string, bool) {
	orgID, global, err := auth.RequireOrg(claims)
	if err != nil {
		return "", false
	}
	if h.userLookup == nil {
		return orgID, true
	}
	if global {
		u, err := h.userLookup.GetByID(ctx, targetUserID)
		if err != nil || u == nil {
			return "", false
		}
		return u.OrgID, true
	}
	u, err := h.userLookup.GetByIDScoped(ctx, targetUserID, orgID)
	if err != nil || u == nil {
		return "", false
	}
	return u.OrgID, true
}

type createRequest struct {
	TargetUserID  string          `json:"target_user_id"`
	CaseRef       string          `json:"case_ref"`
	Reason        string          `json:"reason"`
	ScopeType     string          `json:"scope_type,omitempty"`
	ScopeDateFrom *time.Time      `json:"scope_date_from,omitempty"`
	ScopeDateTo   *time.Time      `json:"scope_date_to,omitempty"`
	ScopeQuery    json.RawMessage `json:"scope_query,omitempty"`
}

type holdResponse struct {
	ID            string  `json:"id"`
	TargetUserID  string  `json:"target_user_id"`
	CaseRef       string  `json:"case_ref"`
	Reason        string  `json:"reason"`
	Status        string  `json:"status"`
	CreatedBy     *string `json:"created_by,omitempty"`
	CreatedAt     string  `json:"created_at"`
	ApprovedAt    *string `json:"approved_at,omitempty"`
	ApprovedBy    *string `json:"approved_by,omitempty"`
	ReleasedAt    *string `json:"released_at,omitempty"`
	ReleasedBy    *string `json:"released_by,omitempty"`
	IsActive      bool    `json:"is_active"`
	ScopeType     string  `json:"scope_type"`
	ScopeDateFrom *string `json:"scope_date_from,omitempty"`
	ScopeDateTo   *string `json:"scope_date_to,omitempty"`
}

type previewRequest struct {
	TargetUserID string          `json:"target_user_id"`
	ScopeType    string          `json:"scope_type"`
	ScopeQuery   json.RawMessage `json:"scope_query"`
}

type previewResponse struct {
	ScopeType       string  `json:"scope_type"`
	SelectorHash    string  `json:"selector_hash"`
	MatchedRows     int     `json:"matched_rows"`
	OldestCreatedAt *string `json:"oldest_created_at,omitempty"`
	NewestCreatedAt *string `json:"newest_created_at,omitempty"`
	Explanation     string  `json:"explanation"`
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
	claims, ok := requirePrivilegedAdmin(w, r)
	if !ok {
		return
	}

	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		h.recordAdmin(r, "apply_hold_requested", "", http.StatusBadRequest, false, map[string]any{"error": "invalid_json"})
		return
	}

	targetOrgID, ok := h.resolveTargetOrg(r.Context(), req.TargetUserID, claims)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "target user not found"})
		h.recordAdmin(r, "apply_hold_requested", req.TargetUserID, http.StatusNotFound, false, map[string]any{
			"error_code": "target_user_not_found",
		})
		return
	}

	hold, err := h.svc.CreateScopedHoldInOrg(
		r.Context(),
		req.TargetUserID,
		req.CaseRef,
		req.Reason,
		claims.UserID,
		targetOrgID,
		req.ScopeType,
		req.ScopeDateFrom,
		req.ScopeDateTo,
	)
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
		case IsUnsupportedScope(err):
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "unsupported scope_type"})
			h.recordAdmin(r, "apply_hold_requested", req.TargetUserID, http.StatusBadRequest, false, map[string]any{
				"error_code": "unsupported_scope_type",
			})
		case IsInvalidScopeRange(err):
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid scope range"})
			h.recordAdmin(r, "apply_hold_requested", req.TargetUserID, http.StatusBadRequest, false, map[string]any{
				"error_code": "invalid_scope_range",
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
		"scope_type":     hold.ScopeType,
	})
}

func (h *Handler) Preview(w http.ResponseWriter, r *http.Request) {
	claims, ok := requirePrivilegedAdmin(w, r)
	if !ok {
		return
	}
	var req previewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		h.recordAdmin(r, "preview_hold_scope", "", http.StatusBadRequest, false, map[string]any{"error_code": "invalid_json"})
		return
	}
	if req.ScopeType != ScopeQuery {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "unsupported scope_type"})
		h.recordAdmin(r, "preview_hold_scope", req.TargetUserID, http.StatusBadRequest, false, map[string]any{
			"error_code": "unsupported_scope_type",
			"scope_type": req.ScopeType,
		})
		return
	}
	targetOrgID, ok := h.resolveTargetOrg(r.Context(), req.TargetUserID, claims)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "target user not found"})
		h.recordAdmin(r, "preview_hold_scope", req.TargetUserID, http.StatusNotFound, false, map[string]any{
			"error_code": "target_user_not_found",
		})
		return
	}
	result, err := h.svc.PreviewQueryScopeInOrg(r.Context(), req.TargetUserID, targetOrgID, req.ScopeQuery)
	if err != nil {
		switch {
		case IsInvalidSelector(err), IsValidation(err):
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid scope query"})
			h.recordAdmin(r, "preview_hold_scope", req.TargetUserID, http.StatusBadRequest, false, map[string]any{
				"error_code": "invalid_scope_query",
				"scope_type": ScopeQuery,
			})
		case IsNotConfigured(err):
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "legal hold not configured"})
			h.recordAdmin(r, "preview_hold_scope", req.TargetUserID, http.StatusServiceUnavailable, false, map[string]any{
				"error_code": "not_configured",
				"scope_type": ScopeQuery,
			})
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "scope preview failed"})
			h.recordAdmin(r, "preview_hold_scope", req.TargetUserID, http.StatusInternalServerError, false, map[string]any{
				"error_code": "internal_error",
				"scope_type": ScopeQuery,
			})
		}
		return
	}
	resp := previewResponse{
		ScopeType:    result.ScopeType,
		SelectorHash: result.SelectorHash,
		MatchedRows:  result.MatchedRows,
		Explanation:  result.Explanation,
	}
	if result.OldestCreatedAt != nil {
		s := result.OldestCreatedAt.UTC().Format(time.RFC3339)
		resp.OldestCreatedAt = &s
	}
	if result.NewestCreatedAt != nil {
		s := result.NewestCreatedAt.UTC().Format(time.RFC3339)
		resp.NewestCreatedAt = &s
	}
	writeJSON(w, http.StatusOK, resp)
	h.recordAdmin(r, "preview_hold_scope", req.TargetUserID, http.StatusOK, true, map[string]any{
		"scope_type":    ScopeQuery,
		"selector_hash": result.SelectorHash,
		"matched_rows":  result.MatchedRows,
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
	claims, ok := requirePrivilegedAdmin(w, r)
	if !ok {
		return
	}
	orgID, ok := h.orgScopeForClaims(claims)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "missing id"})
		return
	}

	hold, err := h.svc.ApproveInOrg(r.Context(), id, claims.UserID, orgID)
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
	claims, ok := requirePrivilegedAdmin(w, r)
	if !ok {
		return
	}
	orgID, ok := h.orgScopeForClaims(claims)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "missing id"})
		return
	}

	hold, err := h.svc.RejectInOrg(r.Context(), id, claims.UserID, orgID)
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
	claims, ok := requirePrivilegedAdmin(w, r)
	if !ok {
		return
	}
	orgID, ok := h.orgScopeForClaims(claims)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "missing id"})
		return
	}

	// PR-L5 BREAKING CHANGE: ReleaseHold теперь RequestRelease
	// (active → release_pending). Требуется ApproveRelease от второго admin.
	hold, err := h.svc.ReleaseHoldInOrg(r.Context(), id, claims.UserID, orgID)
	if err != nil {
		switch {
		case IsNotFound(err):
			writeJSON(w, http.StatusNotFound, errorResponse{Error: "hold not found"})
			h.recordAdmin(r, "request_release", id, http.StatusNotFound, false, map[string]any{
				"error_code": "not_found",
			})
		case IsPendingNotReleasable(err):
			writeJSON(w, http.StatusConflict, errorResponse{Error: "hold is pending, use reject to cancel"})
			h.recordAdmin(r, "request_release", id, http.StatusConflict, false, map[string]any{
				"error_code": "pending_not_releasable",
			})
		case IsAlreadyReleasePending(err):
			writeJSON(w, http.StatusConflict, errorResponse{Error: "release already pending for this hold"})
			h.recordAdmin(r, "request_release", id, http.StatusConflict, false, map[string]any{
				"error_code": "already_release_pending",
			})
		case IsNotActive(err):
			writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": "already_released"})
			h.recordAdmin(r, "request_release", id, http.StatusOK, true, map[string]any{"status": "already_released"})
		case IsValidation(err):
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request"})
			h.recordAdmin(r, "request_release", id, http.StatusBadRequest, false, map[string]any{"error_code": "validation_failed"})
		case IsNotConfigured(err):
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "legal hold not configured"})
			h.recordAdmin(r, "request_release", id, http.StatusServiceUnavailable, false, map[string]any{"error_code": "not_configured"})
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "hold release request failed"})
			h.recordAdmin(r, "request_release", id, http.StatusInternalServerError, false, map[string]any{"error_code": "internal_error"})
		}
		return
	}

	writeJSON(w, http.StatusOK, toResponse(hold))
	h.recordAdmin(r, "request_release", hold.ID, http.StatusOK, true, map[string]any{
		"target_user_id": hold.TargetUserID,
		"case_ref_hash":  h.tokens.Tokenize(hold.CaseRef),
		"new_status":     string(hold.Status),
	})
}

// ApproveRelease — POST /api/legal-holds/{id}/approve-release.
// PR-L5: 4-eyes перевод release_pending → released.
// approver должен отличаться от того, кто запросил release.
func (h *Handler) ApproveRelease(w http.ResponseWriter, r *http.Request) {
	claims, ok := requirePrivilegedAdmin(w, r)
	if !ok {
		return
	}
	orgID, ok := h.orgScopeForClaims(claims)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "missing id"})
		return
	}

	hold, err := h.svc.ApproveReleaseInOrg(r.Context(), id, claims.UserID, orgID)
	if err != nil {
		switch {
		case IsNotFound(err):
			writeJSON(w, http.StatusNotFound, errorResponse{Error: "hold not found"})
			h.recordAdmin(r, "approve_release", id, http.StatusNotFound, false, map[string]any{"error_code": "not_found"})
		case IsNotReleasePending(err):
			writeJSON(w, http.StatusConflict, errorResponse{Error: "hold is not awaiting release approval"})
			h.recordAdmin(r, "approve_release", id, http.StatusConflict, false, map[string]any{"error_code": "not_release_pending"})
		case IsSelfReleaseApproval(err):
			writeJSON(w, http.StatusForbidden, errorResponse{Error: "release approver must differ from release requester (4-eyes policy)"})
			h.recordAdmin(r, "approve_release", id, http.StatusForbidden, false, map[string]any{"error_code": "self_release_approval"})
		case IsNotConfigured(err):
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "legal hold not configured"})
			h.recordAdmin(r, "approve_release", id, http.StatusServiceUnavailable, false, map[string]any{"error_code": "not_configured"})
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "approve release failed"})
			h.recordAdmin(r, "approve_release", id, http.StatusInternalServerError, false, map[string]any{"error_code": "internal_error"})
		}
		return
	}

	writeJSON(w, http.StatusOK, toResponse(hold))
	h.recordAdmin(r, "approve_release", hold.ID, http.StatusOK, true, map[string]any{
		"target_user_id": hold.TargetUserID,
		"case_ref_hash":  h.tokens.Tokenize(hold.CaseRef),
	})
}

// RejectRelease — POST /api/legal-holds/{id}/reject-release.
// PR-L5: перевод release_pending → active (release rejected).
func (h *Handler) RejectRelease(w http.ResponseWriter, r *http.Request) {
	claims, ok := requirePrivilegedAdmin(w, r)
	if !ok {
		return
	}
	orgID, ok := h.orgScopeForClaims(claims)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "missing id"})
		return
	}

	hold, err := h.svc.RejectReleaseInOrg(r.Context(), id, claims.UserID, orgID)
	if err != nil {
		switch {
		case IsNotFound(err):
			writeJSON(w, http.StatusNotFound, errorResponse{Error: "hold not found"})
			h.recordAdmin(r, "reject_release", id, http.StatusNotFound, false, map[string]any{"error_code": "not_found"})
		case IsNotReleasePending(err):
			writeJSON(w, http.StatusConflict, errorResponse{Error: "hold is not awaiting release approval"})
			h.recordAdmin(r, "reject_release", id, http.StatusConflict, false, map[string]any{"error_code": "not_release_pending"})
		case IsNotConfigured(err):
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "legal hold not configured"})
			h.recordAdmin(r, "reject_release", id, http.StatusServiceUnavailable, false, map[string]any{"error_code": "not_configured"})
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "reject release failed"})
			h.recordAdmin(r, "reject_release", id, http.StatusInternalServerError, false, map[string]any{"error_code": "internal_error"})
		}
		return
	}

	writeJSON(w, http.StatusOK, toResponse(hold))
	h.recordAdmin(r, "reject_release", hold.ID, http.StatusOK, true, map[string]any{
		"target_user_id": hold.TargetUserID,
		"case_ref_hash":  h.tokens.Tokenize(hold.CaseRef),
		"new_status":     string(hold.Status),
	})
}

// BulkApprove — POST /api/legal-holds/bulk-approve. Admin-only.
// Body: {"ids": ["id-1", "id-2", ...]}
// Per-item semantics: partial failures are reported per-item.
func (h *Handler) BulkApprove(w http.ResponseWriter, r *http.Request) {
	claims, ok := requirePrivilegedAdmin(w, r)
	if !ok {
		return
	}
	orgID, ok := h.orgScopeForClaims(claims)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if len(req.IDs) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "ids required"})
		return
	}

	results, err := h.svc.BulkApproveInOrg(r.Context(), req.IDs, claims.UserID, orgID)
	if err != nil {
		if IsNotConfigured(err) {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "legal hold not configured"})
			return
		}
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	successCount, failureCount := 0, 0
	for _, res := range results {
		if res.Success {
			successCount++
		} else {
			failureCount++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"results":       results,
		"success_count": successCount,
		"failure_count": failureCount,
	})
	h.recordAdmin(r, "bulk_approve", "", http.StatusOK, failureCount == 0, map[string]any{
		"requested": len(req.IDs),
		"success":   successCount,
		"failures":  failureCount,
	})
}

// BulkReject — POST /api/legal-holds/bulk-reject. Admin-only.
// Body: {"ids": [...]}
func (h *Handler) BulkReject(w http.ResponseWriter, r *http.Request) {
	claims, ok := requirePrivilegedAdmin(w, r)
	if !ok {
		return
	}
	orgID, ok := h.orgScopeForClaims(claims)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if len(req.IDs) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "ids required"})
		return
	}

	results, err := h.svc.BulkRejectInOrg(r.Context(), req.IDs, claims.UserID, orgID)
	if err != nil {
		if IsNotConfigured(err) {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "legal hold not configured"})
			return
		}
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	successCount, failureCount := 0, 0
	for _, res := range results {
		if res.Success {
			successCount++
		} else {
			failureCount++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"results":       results,
		"success_count": successCount,
		"failure_count": failureCount,
	})
	h.recordAdmin(r, "bulk_reject", "", http.StatusOK, failureCount == 0, map[string]any{
		"requested": len(req.IDs),
		"success":   successCount,
		"failures":  failureCount,
	})
}

// PendingSLA — GET /api/legal-holds/pending-sla?threshold_hours=N.
// PR-L5: SLA visibility. Возвращает pending holds старше threshold.
// Default threshold: 24 hours.
func (h *Handler) PendingSLA(w http.ResponseWriter, r *http.Request) {
	claims, ok := requirePrivilegedAdmin(w, r)
	if !ok {
		return
	}
	orgID, ok := h.orgScopeForClaims(claims)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}

	thresholdHours := 24
	if s := r.URL.Query().Get("threshold_hours"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			thresholdHours = n
		}
	}
	threshold := time.Duration(thresholdHours) * time.Hour

	holds, err := h.svc.PendingOlderThanInOrg(r.Context(), threshold, orgID)
	if err != nil {
		if IsNotConfigured(err) {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "legal hold not configured"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal"})
		return
	}

	out := make([]holdResponse, 0, len(holds))
	for i := range holds {
		out = append(out, toResponse(&holds[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"holds":           out,
		"count":           len(out),
		"threshold_hours": thresholdHours,
	})
}

// List — GET /api/legal-holds. Admin-only. Возвращает все holds
// (active + released) в порядке active-first, created_at DESC.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	claims, ok := requirePrivilegedAdmin(w, r)
	if !ok {
		return
	}
	orgID, ok := h.orgScopeForClaims(claims)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}

	holds, err := h.svc.ListInOrg(r.Context(), orgID)
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
		ScopeType:    h.ScopeType,
	}
	if r.ScopeType == "" {
		r.ScopeType = ScopeWholeUser
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
	if h.ScopeDateFrom != nil {
		s := h.ScopeDateFrom.UTC().Format(time.RFC3339)
		r.ScopeDateFrom = &s
	}
	if h.ScopeDateTo != nil {
		s := h.ScopeDateTo.UTC().Format(time.RFC3339)
		r.ScopeDateTo = &s
	}
	return r
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

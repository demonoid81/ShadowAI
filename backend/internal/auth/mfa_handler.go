//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// PR-E1.1: MFA and break-glass HTTP handlers.
package auth

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/shadowai/backend/internal/adminaudit"
)

// MFAConfig holds MFA/break-glass config values extracted from the app config.
// Used to avoid importing the config package (which would create an import cycle
// through audit → auth).
type MFAConfig struct {
	MFATOTPIssuer        string
	BreakGlassEnabled    bool
	BreakGlassSecretHash string
	BreakGlassJWTTTL     time.Duration
}

// MFAHandler serves MFA and break-glass endpoints.
// Routes (all public — no AuthMiddleware):
//   POST /api/auth/mfa/verify         — submit TOTP code after password check
//   POST /api/auth/break-glass        — emergency admin access
//
// Admin-authenticated routes (wire with RequireRole(admin)):
//   POST /api/auth/mfa/setup          — generate TOTP provisioning URI
//   POST /api/auth/mfa/confirm        — confirm TOTP code and enable MFA
//   DELETE /api/auth/mfa              — disable MFA for calling admin
type MFAHandler struct {
	service     *Service
	cfg         MFAConfig
	adminAudit  adminaudit.Recorder
	bgLimiter   *BreakGlassRateLimiter
	bgLimiterMu sync.Mutex
}

// NewMFAHandler creates an MFAHandler. Must only be called in enterprise builds.
func NewMFAHandler(svc *Service, cfg MFAConfig, adminAudit adminaudit.Recorder) *MFAHandler {
	return &MFAHandler{
		service:    svc,
		cfg:        cfg,
		adminAudit: adminAudit,
		bgLimiter:  &BreakGlassRateLimiter{},
	}
}

// ---------------------------------------------------------------------------
// POST /api/auth/mfa/verify
// ---------------------------------------------------------------------------

type mfaVerifyRequest struct {
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code"`
}

// MFAVerify validates the TOTP code after a password-based login challenge.
func (h *MFAHandler) MFAVerify(w http.ResponseWriter, r *http.Request) {
	var req mfaVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if req.MFAToken == "" || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "mfa_token and code are required"})
		return
	}

	userID, err := h.service.VerifyMFAChallenge(req.MFAToken)
	if err != nil {
		h.recordAudit(r, nil, "mfa_failed", http.StatusUnauthorized, false, map[string]any{
			"reason": "invalid_mfa_token",
		})
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid or expired mfa_token"})
		return
	}

	if err := h.service.ValidateTOTPCode(r.Context(), userID, req.Code); err != nil {
		h.recordAudit(r, &userID, "mfa_failed", http.StatusUnauthorized, false, map[string]any{
			"reason": "wrong_code",
		})
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid MFA code"})
		return
	}

	u, err := h.service.GetRepo().GetByID(r.Context(), userID)
	if err != nil || !u.IsActive {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid credentials"})
		return
	}

	token, err := h.service.generateMFAToken(u)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal"})
		return
	}

	h.recordAudit(r, &userID, "mfa_verified", http.StatusOK, true, nil)
	writeJSON(w, http.StatusOK, loginResponse{Token: token})
}

// ---------------------------------------------------------------------------
// POST /api/auth/mfa/setup  (requires admin auth)
// ---------------------------------------------------------------------------

// MFASetup generates a TOTP provisioning URI and returns a setup_token.
// The secret is NOT saved to DB yet — it's embedded in the setup_token JWT.
// The user must scan the QR code and call /mfa/confirm with a valid code
// to activate MFA. This prevents lockout if the user loses the URI.
func (h *MFAHandler) MFASetup(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}

	issuer := h.cfg.MFATOTPIssuer
	uri, _, encSecret, err := h.service.GenerateTOTPSecret(issuer, claims.Email)
	if err != nil {
		log.Printf("mfa setup: generate: %v", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal"})
		return
	}

	// Return setup_token containing the pending secret (not yet in DB).
	setupToken, err := h.service.IssueSetupToken(claims.UserID, encSecret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal"})
		return
	}

	h.recordAudit(r, &claims.UserID, "mfa_challenge_required", http.StatusOK, true, nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"uri":         uri,
		"setup_token": setupToken,
	})
}

// ---------------------------------------------------------------------------
// POST /api/auth/mfa/confirm  (requires admin auth)
// ---------------------------------------------------------------------------

// MFAConfirm validates the first TOTP code using the pending setup_token,
// then saves the secret to DB (enabling MFA). Only succeeds after a valid code
// is provided — prevents lockout from saving a secret the user can't access.
func (h *MFAHandler) MFAConfirm(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}

	var req struct {
		SetupToken string `json:"setup_token"`
		Code       string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" || req.SetupToken == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "setup_token and code are required"})
		return
	}

	// Verify setup_token belongs to the calling user.
	tokenUserID, encSecret, err := h.service.VerifySetupToken(req.SetupToken)
	if err != nil || tokenUserID != claims.UserID {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid or expired setup_token"})
		return
	}

	// Decrypt and validate the TOTP code against the pending secret.
	plainSecret, err := decryptTOTPSecret(h.service.jwtSecret, encSecret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal"})
		return
	}
	if !validateTOTPCode(plainSecret, req.Code) {
		h.recordAudit(r, &claims.UserID, "mfa_failed", http.StatusUnauthorized, false, map[string]any{
			"reason": "invalid_setup_code",
		})
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid MFA code"})
		return
	}

	// Code is valid — now save the secret to DB and enable MFA.
	// SetTOTPSecret also bumps token_version to invalidate existing sessions.
	if err := h.service.GetRepo().SetTOTPSecret(r.Context(), claims.UserID, encSecret); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal"})
		return
	}

	h.recordAudit(r, &claims.UserID, "mfa_verified", http.StatusOK, true, map[string]any{
		"action": "mfa_setup_confirmed",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_enabled"})
}

// ---------------------------------------------------------------------------
// DELETE /api/auth/mfa  (requires admin auth)
// ---------------------------------------------------------------------------

// MFADisable removes MFA for the authenticated admin.
func (h *MFAHandler) MFADisable(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	if err := h.service.GetRepo().ClearTOTPSecret(r.Context(), claims.UserID); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal"})
		return
	}
	h.recordAudit(r, &claims.UserID, "mfa_disabled", http.StatusOK, true, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_disabled"})
}

// ---------------------------------------------------------------------------
// POST /api/auth/break-glass
// ---------------------------------------------------------------------------

type breakGlassRequest struct {
	Secret string `json:"secret"`
}

// BreakGlass provides emergency admin access using the break-glass credential.
func (h *MFAHandler) BreakGlass(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.BreakGlassEnabled {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: "break-glass access not enabled on this instance"})
		return
	}

	// Rate limit globally.
	h.bgLimiterMu.Lock()
	allowed := h.bgLimiter.Allow()
	h.bgLimiterMu.Unlock()
	if !allowed {
		h.recordAudit(r, nil, "break_glass_login_failed", http.StatusTooManyRequests, false, map[string]any{
			"reason": "rate_limited",
		})
		writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: "too many break-glass attempts; try again later"})
		return
	}

	var req breakGlassRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}

	token, err := h.service.BreakGlassLogin(r.Context(), req.Secret, h.cfg.BreakGlassSecretHash, h.cfg.BreakGlassJWTTTL)
	if err != nil {
		log.Printf("break-glass: failed from %s: %v", r.RemoteAddr, err)
		h.recordAudit(r, nil, "break_glass_login_failed", http.StatusUnauthorized, false, map[string]any{
			"reason": "invalid_secret",
			// Intentionally no IP in metadata — audit log is append-only; RemoteAddr only in app log.
		})
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid break-glass credentials"})
		return
	}

	log.Printf("BREAK-GLASS: successful emergency login from %s — rotate credentials after use", r.RemoteAddr)
	h.recordAudit(r, nil, "break_glass_login_success", http.StatusOK, true, map[string]any{
		"ttl_hours": h.cfg.BreakGlassJWTTTL.Hours(),
		"warning":   "rotate BREAK_GLASS_SECRET_HASH after this session",
	})
	writeJSON(w, http.StatusOK, loginResponse{Token: token})
}

// ---------------------------------------------------------------------------
// Audit helper
// ---------------------------------------------------------------------------

func (h *MFAHandler) recordAudit(r *http.Request, userID *string, action string, status int, success bool, meta map[string]any) {
	if h.adminAudit == nil {
		return
	}
	if meta == nil {
		meta = map[string]any{}
	}
	h.adminAudit.Record(r.Context(), adminaudit.Event{
		ActorUserID: userID,
		Action:      action,
		Resource:    "auth_session",
		Path:        r.URL.Path,
		Method:      r.Method,
		StatusCode:  status,
		Success:     success,
		Metadata:    meta,
	})
}

//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
//
// PR-E1: OIDC login/callback HTTP handlers.
//
// Flow:
//
//	Browser → GET /api/auth/oidc/login
//	          ↓ redirects to IdP with state+nonce cookies
//	        IdP → GET /api/auth/oidc/callback?code=...&state=...
//	          ↓ validates ID token, syncs user, issues internal JWT
//	Browser ← {"token":"<jwt>"}
//
// The issued JWT is identical to password login — proxy/governance/audit
// are completely unchanged.
package oidcauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/auth"
)

// Handler serves OIDC login and callback routes.
type Handler struct {
	cfg        *Config
	provider   *gooidc.Provider
	oauthCfg   oauth2.Config
	verifier   *gooidc.IDTokenVerifier
	syncer     *UserSyncer
	authSvc    *auth.Service
	adminAudit adminaudit.Recorder
	states     *StateStore
	// secure determines if cookies use the Secure flag (false only in dev/test).
	secure bool
}

// NewHandler initialises the OIDC handler. ctx is used only for provider discovery.
func NewHandler(
	ctx context.Context,
	cfg *Config,
	syncer *UserSyncer,
	authSvc *auth.Service,
	adminAudit adminaudit.Recorder,
	secure bool,
) (*Handler, error) {
	provider, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: provider discovery %s: %w", cfg.IssuerURL, err)
	}
	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}
	verifier := provider.Verifier(&gooidc.Config{ClientID: cfg.ClientID})
	return &Handler{
		cfg:        cfg,
		provider:   provider,
		oauthCfg:   oauthCfg,
		verifier:   verifier,
		syncer:     syncer,
		authSvc:    authSvc,
		adminAudit: adminAudit,
		states:     NewStateStore(),
		secure:     secure,
	}, nil
}

// Login redirects the browser to the IdP authorization endpoint.
// Generates state and nonce; stores them in short-lived HttpOnly cookies.
//
// GET /api/auth/oidc/login
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	state, nonce, err := h.states.New()
	if err != nil {
		log.Printf("oidc: login state gen: %v", err)
		writeOIDCError(w, http.StatusInternalServerError, "oidc_init_failed")
		return
	}
	SetCookies(w, state, nonce, h.secure)
	authURL := h.oauthCfg.AuthCodeURL(state, gooidc.Nonce(nonce))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback exchanges the authorization code, validates the ID token, syncs the
// user, and returns an internal JWT.
//
// GET /api/auth/oidc/callback?code=...&state=...
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. CSRF: verify that the state query param matches the browser-bound cookie
	// AND is present in the server-side store. Two checks:
	//   (a) Cookie equality: ties the flow to the initiating browser session.
	//       Without this, the server-side store prevents CSRF from random state values
	//       but not from an attacker replaying a state from the victim's store.
	//   (b) Consume from store: verifies the state was issued by this server + not reused.
	stateParam := r.URL.Query().Get("state")
	stateCookie, cookieErr := r.Cookie(stateCookieName)
	if cookieErr != nil || stateCookie.Value != stateParam {
		h.recordFail(r, "state_cookie_mismatch", "")
		writeOIDCError(w, http.StatusBadRequest, "invalid_state")
		return
	}
	expectedNonce, err := h.states.Consume(stateParam)
	if err != nil {
		h.recordFail(r, "state_mismatch", "")
		writeOIDCError(w, http.StatusBadRequest, "invalid_state")
		return
	}
	ClearCookies(w)

	// 2. Exchange code for tokens.
	code := r.URL.Query().Get("code")
	if code == "" {
		h.recordFail(r, "missing_code", "")
		writeOIDCError(w, http.StatusBadRequest, "missing_code")
		return
	}
	token, err := h.oauthCfg.Exchange(ctx, code)
	if err != nil {
		log.Printf("oidc: token exchange: %v", err)
		h.recordFail(r, "token_exchange_failed", "")
		writeOIDCError(w, http.StatusBadRequest, "token_exchange_failed")
		return
	}

	// 3. Extract and verify ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		h.recordFail(r, "missing_id_token", "")
		writeOIDCError(w, http.StatusBadRequest, "missing_id_token")
		return
	}
	idToken, err := h.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("oidc: id_token verify: %v", err)
		h.recordFail(r, "id_token_invalid", "")
		writeOIDCError(w, http.StatusUnauthorized, "id_token_invalid")
		return
	}

	// 4. Verify nonce to prevent replay attacks.
	var claimMap map[string]any
	if err := idToken.Claims(&claimMap); err != nil {
		h.recordFail(r, "claims_parse_failed", "")
		writeOIDCError(w, http.StatusInternalServerError, "claims_parse_failed")
		return
	}
	if nonce, _ := claimMap["nonce"].(string); nonce != expectedNonce {
		h.recordFail(r, "nonce_mismatch", "")
		writeOIDCError(w, http.StatusBadRequest, "nonce_mismatch")
		return
	}

	// 5. Extract claims.
	claims := extractClaims(claimMap, h.cfg.DepartmentClaim)
	claims.Subject = idToken.Subject

	// 6. Sync user.
	result, err := h.syncer.Sync(ctx, idToken.Issuer, claims)
	if err != nil {
		log.Printf("oidc: user sync: %v", err)
		h.recordFail(r, "user_sync_failed", claims.Email)
		writeOIDCError(w, http.StatusForbidden, "access_denied")
		return
	}

	// 7. Issue internal JWT.
	jwtStr, err := h.authSvc.GenerateTokenForUserID(ctx, result.User.ID)
	if err != nil {
		log.Printf("oidc: token issue: %v", err)
		h.recordFail(r, "token_issue_failed", claims.Email)
		writeOIDCError(w, http.StatusInternalServerError, "token_issue_failed")
		return
	}

	// 8. Audit.
	h.recordSuccess(r, result, claims)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": jwtStr})
}

// extractClaims parses an ID token claim map into IDTokenClaims.
func extractClaims(c map[string]any, deptClaim string) IDTokenClaims {
	str := func(key string) string {
		if v, ok := c[key].(string); ok {
			return v
		}
		return ""
	}
	// email_verified may be bool or string "true"/"false" depending on IdP.
	emailVerified := false
	switch v := c["email_verified"].(type) {
	case bool:
		emailVerified = v
	case string:
		emailVerified = v == "true"
	}
	claims := IDTokenClaims{
		Email:         str("email"),
		EmailVerified: emailVerified,
		Name:          str("name"),
	}
	if deptClaim != "" {
		claims.Department = str(deptClaim)
	}
	// groups claim may be []interface{} or []string.
	switch v := c["groups"].(type) {
	case []any:
		for _, g := range v {
			if s, ok := g.(string); ok && s != "" {
				claims.Groups = append(claims.Groups, strings.TrimSpace(s))
			}
		}
	case []string:
		claims.Groups = v
	}
	return claims
}

// ---------------------------------------------------------------------------
// Audit helpers
// ---------------------------------------------------------------------------

func (h *Handler) recordSuccess(r *http.Request, result SyncResult, claims IDTokenClaims) {
	if h.adminAudit == nil {
		return
	}
	userID := result.User.ID
	h.adminAudit.Record(r.Context(), adminaudit.Event{
		ActorUserID: &userID,
		Action:      "oidc_login_" + result.Action,
		Resource:    "oidc_session",
		TargetID:    result.User.ID,
		Path:        r.URL.Path,
		Method:      r.Method,
		StatusCode:  http.StatusOK,
		Success:     true,
		Metadata: map[string]any{
			"issuer":       h.cfg.IssuerURL,
			"role_mapped":  result.RoleMapped,
			"dept_synced":  result.DeptSynced,
			"action":       result.Action,
			// NOTE: no raw token values, no email, no sub — PII-minimized.
		},
	})
}

func (h *Handler) recordFail(r *http.Request, reason, _ string) {
	if h.adminAudit == nil {
		return
	}
	h.adminAudit.Record(r.Context(), adminaudit.Event{
		ActorUserID: nil,
		Action:      "oidc_login_failed",
		Resource:    "oidc_session",
		Path:        r.URL.Path,
		Method:      r.Method,
		StatusCode:  http.StatusUnauthorized,
		Success:     false,
		Metadata: map[string]any{
			"reason": reason,
			"issuer": h.cfg.IssuerURL,
			// No email or token values in failure audit (attacker-controlled input).
		},
	})
}

func writeOIDCError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}

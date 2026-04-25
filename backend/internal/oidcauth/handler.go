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

	// 5. Extract claims (including amr/acr for MFA enforcement).
	claims := extractClaims(claimMap, h.cfg.DepartmentClaim)
	claims.Subject = idToken.Subject

	// 5a. PR-E3: check IdP MFA claims BEFORE sync.
	claims.MFAVerifiedByIdP = h.cfg.CheckMFAClaims(claims)

	// 5b. PR-E3: pre-sync admin MFA gate.
	//
	// We must enforce MFA BEFORE calling syncer.Sync() because Sync() persists
	// changes (role upgrade from groups, email, dept, timestamps). Scenario:
	//   - existing non-admin user logs in with admins group and no MFA
	//   - if Sync() ran first, DB role would be upgraded to admin
	//   - then MFA denial would come too late
	//
	// We determine "would this become admin?" using wouldBeAdmin, which checks:
	//   1. What role the groups claim maps to (via cfg.MapRole)
	//   2. What role the existing user already has in DB (via subject lookup)
	//
	// This pre-flight check adds one DB lookup but prevents dirty writes on denial.
	if h.cfg.RequireMFAForAdmin && !claims.MFAVerifiedByIdP {
		if admin, reason := h.wouldBeAdmin(ctx, idToken.Issuer, claims); admin {
			log.Printf("oidc: admin MFA not confirmed (amr=%v acr=%q reason=%s)",
				claims.AMR, claims.ACR, reason)
			h.recordMFADenied(r, reason, claims)
			writeOIDCError(w, http.StatusForbidden, "admin_mfa_required")
			return
		}
	}

	// 6. Sync user — safe to write now that MFA is either confirmed or not required.
	result, err := h.syncer.Sync(ctx, idToken.Issuer, claims)
	if err != nil {
		log.Printf("oidc: user sync: %v", err)
		h.recordFail(r, "user_sync_failed", claims.Email)
		writeOIDCError(w, http.StatusForbidden, "access_denied")
		return
	}

	// 7. Issue internal JWT — MFAVerified=true if IdP confirmed MFA.
	jwtStr, err := h.authSvc.GenerateTokenForUserIDWithMFA(ctx, result.User.ID, claims.MFAVerifiedByIdP)
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
		ACR:           str("acr"),
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
	// amr claim: []interface{} or []string.
	switch v := c["amr"].(type) {
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s != "" {
				claims.AMR = append(claims.AMR, strings.ToLower(strings.TrimSpace(s)))
			}
		}
	case []string:
		for _, s := range v {
			claims.AMR = append(claims.AMR, strings.ToLower(s))
		}
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

// wouldBeAdmin returns (true, reason) if processing this callback would result
// in an admin session. Checks three paths in order:
//  1. OIDC groups claim maps to admin role.
//  2. Existing user found by subject already has admin role.
//  3. OIDC_LINK_BY_EMAIL=true: email is verified and existing user found by email
//     already has admin role (the email-link path in Sync would link this session).
//
// Called BEFORE Sync() to prevent dirty writes when admin MFA is denied.
func (h *Handler) wouldBeAdmin(ctx context.Context, issuer string, claims IDTokenClaims) (bool, string) {
	// 1. Groups → admin mapping.
	if mappedRole := h.cfg.MapRole(claims.Groups); mappedRole == auth.RoleAdmin {
		return true, "groups_map_to_admin"
	}
	// 2. Existing user by subject already admin.
	if claims.Subject != "" {
		existing, err := h.syncer.GetBySubject(ctx, issuer, claims.Subject)
		if err == nil && existing != nil && existing.Role == auth.RoleAdmin {
			return true, "existing_admin_role"
		}
	}
	// 3. Email-link path: OIDC_LINK_BY_EMAIL=true + verified email → would link to existing admin.
	// If email is unverified we skip this check (email-link is also blocked for unverified email).
	if h.cfg.LinkByEmail && claims.EmailVerified && claims.Email != "" {
		byEmail, err := h.syncer.GetByEmail(ctx, claims.Email)
		if err == nil && byEmail != nil && byEmail.Role == auth.RoleAdmin {
			return true, "email_link_to_admin"
		}
	}
	return false, ""
}

// recordMFADenied emits an admin event when an OIDC admin login is denied
// because the IdP did not confirm MFA.
//
// ActorUserID is nil — at this point we don't have a verified UUID (the check
// fires before Sync() in the pre-flight path, and the sub/email may not exist
// in DB). Identification context is preserved in metadata instead.
func (h *Handler) recordMFADenied(r *http.Request, reason string, claims IDTokenClaims) {
	if h.adminAudit == nil {
		return
	}
	h.adminAudit.Record(r.Context(), adminaudit.Event{
		ActorUserID: nil, // not a UUID — never put "preflight:<sub>" here
		Action:      "oidc_mfa_not_confirmed",
		Resource:    "oidc_session",
		Path:        r.URL.Path,
		Method:      r.Method,
		StatusCode:  http.StatusForbidden,
		Success:     false,
		Metadata: map[string]any{
			"issuer":       h.cfg.IssuerURL,
			"reason":       reason,
			"amr":          claims.AMR,
			"acr":          claims.ACR,
			"required_amr": h.cfg.MFAAMRValues,
			"required_acr": h.cfg.MFAACRValues,
			// No sub/email — PII-minimized; reason encodes which path triggered denial.
		},
	})
}

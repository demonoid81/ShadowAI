//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// PR-E1: OIDC Enterprise Auth v1.
//
// Package oidcauth implements OIDC login for enterprise deployments.
// After a successful OIDC callback the user receives the standard internal JWT,
// so the proxy/governance/audit pipeline is unchanged.
package oidcauth

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/shadowai/backend/internal/config"
)

// Config holds OIDC configuration resolved from Config.
type Config struct {
	IssuerURL        string
	ClientID         string
	ClientSecret     string
	RedirectURL      string
	Scopes           []string
	RoleMap          map[string]string // OIDC group → ShadowAI role
	DepartmentClaim  string
	AutoProvision    bool
	LinkByEmail      bool
	// AllowUnverifiedEmail disables the email_verified check.
	// DANGEROUS: only set true for IdPs that don't support email_verified
	// (e.g. some enterprise SAML-bridged providers). When false (default),
	// link_by_email, auto_provision, and email sync reject unverified emails
	// to prevent account-takeover via unverified email registration.
	AllowUnverifiedEmail bool

	// PR-E3: IdP MFA enforcement.
	// RequireMFAForAdmin — if true, OIDC callback for admin-role users must
	// include MFA-confirming amr or acr claims. Denies login and emits
	// oidc_mfa_not_confirmed admin event if claims are absent or insufficient.
	RequireMFAForAdmin bool
	// MFAAMRValues — AMR claim values that confirm MFA was performed.
	// Checked as a set: if any token amr value is in this set → MFA confirmed.
	// Default: {"mfa","otp","hwk","swk"} — covers Okta, Azure AD, Google Workspace.
	MFAAMRValues []string
	// MFAACRValues — ACR claim values that confirm MFA.
	// Checked as a set: if token acr is in this set → MFA confirmed.
	// Lower priority than AMR: used for IdPs that don't set amr.
	MFAACRValues []string
}

// FromAppConfig builds an OIDCConfig from application config.
// Returns nil if OIDC is disabled.
func FromAppConfig(cfg *config.Config) (*Config, error) {
	if !cfg.OIDCEnabled {
		return nil, nil
	}
	if cfg.OIDCIssuerURL == "" {
		return nil, fmt.Errorf("oidc: OIDC_ISSUER_URL required")
	}
	if cfg.OIDCClientID == "" {
		return nil, fmt.Errorf("oidc: OIDC_CLIENT_ID required")
	}
	if cfg.OIDCClientSecret == "" {
		return nil, fmt.Errorf("oidc: OIDC_CLIENT_SECRET required")
	}
	if cfg.OIDCRedirectURL == "" {
		return nil, fmt.Errorf("oidc: OIDC_REDIRECT_URL required")
	}

	scopes := strings.Fields(cfg.OIDCScopes)
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	roleMap := make(map[string]string)
	if cfg.OIDCRoleMapJSON != "" {
		if err := json.Unmarshal([]byte(cfg.OIDCRoleMapJSON), &roleMap); err != nil {
			return nil, fmt.Errorf("oidc: OIDC_ROLE_MAP_JSON invalid: %w", err)
		}
	}

	deptClaim := cfg.OIDCDepartmentClaim
	if deptClaim == "" {
		deptClaim = "department"
	}

	// PR-E3: MFA enforcement.
	mfaAMR := strings.Fields(strings.ReplaceAll(cfg.OIDCMFAAMRValues, ",", " "))
	if len(mfaAMR) == 0 && cfg.OIDCRequireMFAForAdmin {
		// Default well-known AMR values covering Okta, Azure AD, Google Workspace.
		mfaAMR = []string{"mfa", "otp", "hwk", "swk"}
	}
	mfaACR := strings.Fields(strings.ReplaceAll(cfg.OIDCMFAACRValues, ",", " "))

	return &Config{
		IssuerURL:            cfg.OIDCIssuerURL,
		ClientID:             cfg.OIDCClientID,
		ClientSecret:         cfg.OIDCClientSecret,
		RedirectURL:          cfg.OIDCRedirectURL,
		Scopes:               scopes,
		RoleMap:              roleMap,
		DepartmentClaim:      deptClaim,
		AutoProvision:        cfg.OIDCAutoProvision,
		LinkByEmail:          cfg.OIDCLinkByEmail,
		AllowUnverifiedEmail: cfg.OIDCAllowUnverifiedEmail,
		RequireMFAForAdmin:   cfg.OIDCRequireMFAForAdmin,
		MFAAMRValues:         mfaAMR,
		MFAACRValues:         mfaACR,
	}, nil
}

// CheckMFAClaims returns true if the ID token claims confirm MFA was performed.
//
// Priority:
//  1. AMR: if any value in claims.AMR is in c.MFAAMRValues → MFA confirmed.
//  2. ACR: if claims.ACR is in c.MFAACRValues → MFA confirmed.
//  3. Otherwise: not confirmed.
//
// An empty MFAAMRValues/MFAACRValues means "no AMR/ACR requirement" — only the
// non-empty set is checked. If both are empty, MFA is never confirmed via claims.
func (c *Config) CheckMFAClaims(claims IDTokenClaims) bool {
	if len(c.MFAAMRValues) > 0 {
		for _, tokenAMR := range claims.AMR {
			for _, want := range c.MFAAMRValues {
				if strings.EqualFold(tokenAMR, want) {
					return true
				}
			}
		}
	}
	if len(c.MFAACRValues) > 0 && claims.ACR != "" {
		for _, want := range c.MFAACRValues {
			if strings.EqualFold(claims.ACR, want) {
				return true
			}
		}
	}
	return false
}

// MapRole maps an OIDC groups claim to a ShadowAI role.
// groups is the list of OIDC group names from the token.
// Returns the first matching role found in the role map, or "" if none match.
func (c *Config) MapRole(groups []string) string {
	for _, g := range groups {
		if role, ok := c.RoleMap[g]; ok {
			return role
		}
	}
	return ""
}

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

	return &Config{
		IssuerURL:       cfg.OIDCIssuerURL,
		ClientID:        cfg.OIDCClientID,
		ClientSecret:    cfg.OIDCClientSecret,
		RedirectURL:     cfg.OIDCRedirectURL,
		Scopes:          scopes,
		RoleMap:         roleMap,
		DepartmentClaim: deptClaim,
		AutoProvision:   cfg.OIDCAutoProvision,
		LinkByEmail:     cfg.OIDCLinkByEmail,
	}, nil
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

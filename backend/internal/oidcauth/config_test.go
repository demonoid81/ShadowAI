//go:build enterprise

package oidcauth

import (
	"testing"

	"github.com/shadowai/backend/internal/config"
)

// TestFromAppConfig_Disabled — OIDC_ENABLED=false returns nil, no error.
func TestFromAppConfig_Disabled(t *testing.T) {
	cfg, err := FromAppConfig(&config.Config{OIDCEnabled: false})
	if err != nil {
		t.Fatalf("disabled: unexpected error: %v", err)
	}
	if cfg != nil {
		t.Error("disabled: expected nil config, got non-nil")
	}
}

// TestFromAppConfig_MissingIssuer — OIDC_ENABLED=true without issuer URL → error.
func TestFromAppConfig_MissingIssuer(t *testing.T) {
	_, err := FromAppConfig(&config.Config{
		OIDCEnabled:      true,
		OIDCClientID:     "client",
		OIDCClientSecret: "secret",
		OIDCRedirectURL:  "https://example.com/callback",
	})
	if err == nil {
		t.Error("expected error for missing issuer URL, got nil")
	}
}

// TestFromAppConfig_DefaultScopes — empty OIDC_SCOPES → defaults.
func TestFromAppConfig_DefaultScopes(t *testing.T) {
	cfg, err := FromAppConfig(&config.Config{
		OIDCEnabled:      true,
		OIDCIssuerURL:    "https://idp.example.com",
		OIDCClientID:     "client",
		OIDCClientSecret: "secret",
		OIDCRedirectURL:  "https://example.com/callback",
		OIDCScopes:       "",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Scopes) == 0 {
		t.Error("empty scopes: expected defaults, got empty")
	}
	found := false
	for _, s := range cfg.Scopes {
		if s == "openid" {
			found = true
		}
	}
	if !found {
		t.Errorf("default scopes should include openid, got %v", cfg.Scopes)
	}
}

// TestFromAppConfig_DefaultDepartmentClaim — empty OIDC_DEPARTMENT_CLAIM → "department".
func TestFromAppConfig_DefaultDepartmentClaim(t *testing.T) {
	cfg, _ := FromAppConfig(&config.Config{
		OIDCEnabled:         true,
		OIDCIssuerURL:       "https://idp.example.com",
		OIDCClientID:        "client",
		OIDCClientSecret:    "secret",
		OIDCRedirectURL:     "https://example.com/callback",
		OIDCDepartmentClaim: "",
	})
	if cfg.DepartmentClaim != "department" {
		t.Errorf("DepartmentClaim = %q, want 'department'", cfg.DepartmentClaim)
	}
}

// TestFromAppConfig_InvalidRoleMapJSON — malformed JSON → error.
func TestFromAppConfig_InvalidRoleMapJSON(t *testing.T) {
	_, err := FromAppConfig(&config.Config{
		OIDCEnabled:      true,
		OIDCIssuerURL:    "https://idp.example.com",
		OIDCClientID:     "client",
		OIDCClientSecret: "secret",
		OIDCRedirectURL:  "https://example.com/callback",
		OIDCRoleMapJSON:  "{not valid json",
	})
	if err == nil {
		t.Error("expected error for invalid role_map_json, got nil")
	}
}

// ---------------------------------------------------------------------------
// MapRole tests
// ---------------------------------------------------------------------------

func TestMapRole_Hit(t *testing.T) {
	cfg := &Config{RoleMap: map[string]string{"admins": "admin", "engineers": "user"}}
	if got := cfg.MapRole([]string{"engineers"}); got != "user" {
		t.Errorf("MapRole([engineers]) = %q, want user", got)
	}
}

func TestMapRole_FirstMatch(t *testing.T) {
	cfg := &Config{RoleMap: map[string]string{"admins": "admin", "engineers": "user"}}
	// "admins" listed first → returns "admin"
	got := cfg.MapRole([]string{"admins", "engineers"})
	if got != "admin" {
		t.Errorf("MapRole first match: got %q, want admin", got)
	}
}

func TestMapRole_NoMatch(t *testing.T) {
	cfg := &Config{RoleMap: map[string]string{"admins": "admin"}}
	if got := cfg.MapRole([]string{"unknown-group"}); got != "" {
		t.Errorf("MapRole no match: got %q, want empty", got)
	}
}

func TestMapRole_EmptyGroups(t *testing.T) {
	cfg := &Config{RoleMap: map[string]string{"admins": "admin"}}
	if got := cfg.MapRole(nil); got != "" {
		t.Errorf("MapRole nil groups: got %q, want empty", got)
	}
}

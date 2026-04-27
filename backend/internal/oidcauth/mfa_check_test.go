//go:build enterprise

package oidcauth

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"testing"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/domain"
)

// ---------------------------------------------------------------------------
// CheckMFAClaims tests — AMR/ACR verification logic
// ---------------------------------------------------------------------------

// TestCheckMFAClaims_AMR_OktaStyle — Okta typically sends amr=["mfa","pwd"].
func TestCheckMFAClaims_AMR_OktaStyle(t *testing.T) {
	cfg := &Config{
		RequireMFAForAdmin: true,
		MFAAMRValues:       []string{"mfa", "otp", "hwk", "swk"},
	}
	claims := IDTokenClaims{AMR: []string{"mfa", "pwd"}}
	if !cfg.CheckMFAClaims(claims) {
		t.Error("Okta-style amr=[mfa,pwd] should confirm MFA")
	}
}

// TestCheckMFAClaims_AMR_AzureADStyle — Azure AD sends amr=["mfa"] or amr=["rsa"].
func TestCheckMFAClaims_AMR_AzureADStyle(t *testing.T) {
	cfg := &Config{MFAAMRValues: []string{"mfa", "otp", "hwk", "swk"}}
	claims := IDTokenClaims{AMR: []string{"mfa"}}
	if !cfg.CheckMFAClaims(claims) {
		t.Error("Azure AD-style amr=[mfa] should confirm MFA")
	}
}

// TestCheckMFAClaims_AMR_HardwareKey — FIDO2/WebAuthn hardware key (hwk).
func TestCheckMFAClaims_AMR_HardwareKey(t *testing.T) {
	cfg := &Config{MFAAMRValues: []string{"mfa", "otp", "hwk", "swk"}}
	claims := IDTokenClaims{AMR: []string{"hwk", "pin"}}
	if !cfg.CheckMFAClaims(claims) {
		t.Error("hwk (hardware key) should confirm MFA")
	}
}

// TestCheckMFAClaims_AMR_PasswordOnly — pwd only, no MFA factor.
func TestCheckMFAClaims_AMR_PasswordOnly(t *testing.T) {
	cfg := &Config{MFAAMRValues: []string{"mfa", "otp", "hwk", "swk"}}
	claims := IDTokenClaims{AMR: []string{"pwd"}}
	if cfg.CheckMFAClaims(claims) {
		t.Error("pwd-only amr should NOT confirm MFA")
	}
}

// TestCheckMFAClaims_AMR_Missing — no amr claim in token.
func TestCheckMFAClaims_AMR_Missing(t *testing.T) {
	cfg := &Config{MFAAMRValues: []string{"mfa", "otp", "hwk", "swk"}}
	claims := IDTokenClaims{AMR: nil}
	if cfg.CheckMFAClaims(claims) {
		t.Error("missing amr should NOT confirm MFA")
	}
}

// TestCheckMFAClaims_ACR_Only — IdP expresses MFA via acr only.
func TestCheckMFAClaims_ACR_Only(t *testing.T) {
	cfg := &Config{
		MFAACRValues: []string{"urn:mace:incommon:iap:silver", "mfa"},
	}
	claims := IDTokenClaims{ACR: "urn:mace:incommon:iap:silver"}
	if !cfg.CheckMFAClaims(claims) {
		t.Error("ACR silver should confirm MFA")
	}
}

// TestCheckMFAClaims_ACR_NoMatch — ACR present but not in required set.
func TestCheckMFAClaims_ACR_NoMatch(t *testing.T) {
	cfg := &Config{MFAACRValues: []string{"urn:mace:incommon:iap:silver"}}
	claims := IDTokenClaims{ACR: "urn:mace:incommon:iap:bronze"}
	if cfg.CheckMFAClaims(claims) {
		t.Error("non-matching ACR should NOT confirm MFA")
	}
}

// TestCheckMFAClaims_AMR_Present_NoACRFallback — when AMR is present but
// non-matching, ACR must NOT be consulted even if ACR matches.
// Scenario: IdP sends amr=["pwd"] (password-only) and acr="mfa" (stale/weak).
// Fix: AMR is authoritative when present; ACR is only fallback for AMR-absent tokens.
func TestCheckMFAClaims_AMR_Present_NoACRFallback(t *testing.T) {
	cfg := &Config{
		MFAAMRValues: []string{"mfa", "otp", "hwk"},
		MFAACRValues: []string{"mfa"}, // matches the ACR value below
	}
	// AMR is present (pwd only) but doesn't match; ACR="mfa" looks like MFA but must not win.
	claims := IDTokenClaims{AMR: []string{"pwd"}, ACR: "mfa"}
	if cfg.CheckMFAClaims(claims) {
		t.Error("AMR present but non-matching: must NOT fall back to ACR (ACR='mfa' must not confirm MFA)")
	}
}

// TestCheckMFAClaims_AMR_Absent_UsesACR — AMR absent → ACR fallback is correct.
func TestCheckMFAClaims_AMR_Absent_UsesACR(t *testing.T) {
	cfg := &Config{MFAACRValues: []string{"urn:mace:incommon:iap:silver", "mfa"}}
	claims := IDTokenClaims{AMR: nil, ACR: "mfa"} // no AMR, ACR confirms MFA
	if !cfg.CheckMFAClaims(claims) {
		t.Error("AMR absent + ACR matches: should confirm MFA via ACR fallback")
	}
}

// TestCheckMFAClaims_AMR_Takes_Priority_Over_ACR — AMR match even if ACR empty.
func TestCheckMFAClaims_AMR_Takes_Priority_Over_ACR(t *testing.T) {
	cfg := &Config{
		MFAAMRValues: []string{"otp"},
		MFAACRValues: []string{"silver"},
	}
	// AMR matches → confirmed, even though ACR doesn't match.
	claims := IDTokenClaims{AMR: []string{"otp"}, ACR: "bronze"}
	if !cfg.CheckMFAClaims(claims) {
		t.Error("AMR match should confirm MFA even if ACR doesn't match")
	}
}

// TestCheckMFAClaims_CaseInsensitive — amr values are case-insensitive.
func TestCheckMFAClaims_CaseInsensitive(t *testing.T) {
	cfg := &Config{MFAAMRValues: []string{"mfa"}}
	claims := IDTokenClaims{AMR: []string{"MFA"}} // uppercase from IdP
	if !cfg.CheckMFAClaims(claims) {
		t.Error("AMR comparison must be case-insensitive")
	}
}

// TestCheckMFAClaims_EmptyConfig_NeverConfirms — no AMR/ACR values configured
// → MFA is never confirmed (OIDC_REQUIRE_MFA_FOR_ADMIN with empty config
// would deny all admins; operators must configure at least one value).
func TestCheckMFAClaims_EmptyConfig_NeverConfirms(t *testing.T) {
	cfg := &Config{MFAAMRValues: nil, MFAACRValues: nil}
	claims := IDTokenClaims{AMR: []string{"mfa"}, ACR: "silver"}
	if cfg.CheckMFAClaims(claims) {
		t.Error("empty AMR/ACR config should never confirm MFA")
	}
}

// TestCheckMFAClaims_NonAdmin_Unaffected — the check is purely about claims;
// role enforcement is at the handler level, not in CheckMFAClaims.
func TestCheckMFAClaims_NonAdmin_Unaffected(t *testing.T) {
	// cfg.RequireMFAForAdmin doesn't change what CheckMFAClaims returns;
	// it's only checked by the handler.
	cfg := &Config{
		RequireMFAForAdmin: true,
		MFAAMRValues:       []string{"mfa"},
	}
	// A non-admin user with no MFA claim — CheckMFAClaims returns false, but
	// the handler only enforces when role == admin.
	claims := IDTokenClaims{AMR: nil}
	if cfg.CheckMFAClaims(claims) {
		t.Error("no MFA in claims → false regardless of RequireMFAForAdmin")
	}
}

// ---------------------------------------------------------------------------
// wouldBeAdmin regression tests — email-link path and audit safety
// ---------------------------------------------------------------------------

// TestWouldBeAdmin_EmailLinkToAdmin — regression: OIDC_LINK_BY_EMAIL=true
// + verified email matching an existing admin → wouldBeAdminWith returns
// (true, "email_link_to_admin") using the production function.
func TestWouldBeAdmin_EmailLinkToAdmin(t *testing.T) {
	adminUser := &domain.User{ID: "admin-uuid", Email: "admin@example.com", Role: "admin", IsActive: true}
	cfg := &Config{
		RequireMFAForAdmin: true,
		MFAAMRValues:       []string{"mfa"},
		LinkByEmail:        true,
	}
	claims := IDTokenClaims{
		Subject:       "new-subject-no-existing-match",
		Email:         "admin@example.com",
		EmailVerified: true,
		AMR:           nil,
	}
	mock := &mockPreflightSyncer{
		bySubject: map[string]*domain.User{},
		byEmail:   map[string]*domain.User{"admin@example.com": adminUser},
	}

	// Call the PRODUCTION function, not a local closure.
	admin, reason := wouldBeAdminWith(context.Background(), "https://idp.example.com", claims, cfg, mock)
	if !admin {
		t.Error("wouldBeAdminWith: email-link to existing admin must be detected pre-sync")
	}
	if reason != "email_link_to_admin" {
		t.Errorf("reason = %q, want email_link_to_admin", reason)
	}
}

// TestWouldBeAdmin_EmailLinkUnverified_AllowUnverifiedFalse — unverified email +
// AllowUnverifiedEmail=false must NOT match email-link path.
func TestWouldBeAdmin_EmailLinkUnverified_AllowUnverifiedFalse(t *testing.T) {
	adminUser := &domain.User{ID: "admin-uuid", Email: "admin@example.com", Role: "admin"}
	cfg := &Config{LinkByEmail: true, AllowUnverifiedEmail: false}
	claims := IDTokenClaims{
		Subject:       "new-sub",
		Email:         "admin@example.com",
		EmailVerified: false, // unverified + AllowUnverifiedEmail=false → no link
	}
	mock := &mockPreflightSyncer{
		bySubject: map[string]*domain.User{},
		byEmail:   map[string]*domain.User{"admin@example.com": adminUser},
	}
	admin, reason := wouldBeAdminWith(context.Background(), "https://idp.example.com", claims, cfg, mock)
	if admin {
		t.Errorf("unverified email + AllowUnverifiedEmail=false: must NOT detect admin (got reason=%q)", reason)
	}
}

// TestWouldBeAdmin_EmailLinkUnverified_AllowUnverifiedTrue — unverified email +
// AllowUnverifiedEmail=true mirrors Sync() and MUST match (High fix).
func TestWouldBeAdmin_EmailLinkUnverified_AllowUnverifiedTrue(t *testing.T) {
	adminUser := &domain.User{ID: "admin-uuid", Email: "admin@example.com", Role: "admin"}
	cfg := &Config{
		LinkByEmail:          true,
		AllowUnverifiedEmail: true, // dangerous config, but explicitly supported
	}
	claims := IDTokenClaims{
		Subject:       "new-sub",
		Email:         "admin@example.com",
		EmailVerified: false, // unverified, but AllowUnverifiedEmail=true
	}
	mock := &mockPreflightSyncer{
		bySubject: map[string]*domain.User{},
		byEmail:   map[string]*domain.User{"admin@example.com": adminUser},
	}
	admin, reason := wouldBeAdminWith(context.Background(), "https://idp.example.com", claims, cfg, mock)
	if !admin {
		t.Error("unverified email + AllowUnverifiedEmail=true: preflight must match (mirrors Sync() behaviour)")
	}
	if reason != "email_link_to_admin" {
		t.Errorf("reason = %q, want email_link_to_admin", reason)
	}
}

func TestWouldBeAdmin_ExistingGlobalAdminRole(t *testing.T) {
	globalAdmin := &domain.User{ID: "global-admin-uuid", Role: auth.RoleGlobalAdmin, IsActive: true}
	cfg := &Config{RequireMFAForAdmin: true, MFAAMRValues: []string{"mfa"}}
	claims := IDTokenClaims{Subject: "global-admin-sub", AMR: []string{"pwd"}}
	mock := &mockPreflightSyncer{
		bySubject: map[string]*domain.User{"global-admin-sub": globalAdmin},
		byEmail:   map[string]*domain.User{},
	}

	admin, reason := wouldBeAdminWith(context.Background(), "https://idp.example.com", claims, cfg, mock)
	if !admin {
		t.Fatal("existing global_admin must be treated as privileged admin before OIDC sync")
	}
	if reason != "existing_admin_role" {
		t.Fatalf("reason = %q, want existing_admin_role", reason)
	}
}

// TestRecordMFADenied_ActorUserIDIsNil — regression: preflight denial must use
// ActorUserID=nil, not a fake "preflight:<sub>" string that violates UUID format.
func TestRecordMFADenied_ActorUserIDIsNil(t *testing.T) {
	var captured *adminaudit.Event
	recorder := &captureAuditRecorder{capture: &captured}

	h := &Handler{
		cfg: &Config{
			IssuerURL:    "https://idp.example.com",
			MFAAMRValues: []string{"mfa"},
		},
		adminAudit: recorder,
	}
	req := httptest.NewRequest("GET", "/api/auth/oidc/callback", nil)
	claims := IDTokenClaims{AMR: []string{"pwd"}, ACR: ""}

	h.recordMFADenied(req, "email_link_to_admin", claims)

	if captured == nil {
		t.Fatal("audit event not recorded")
	}
	if captured.ActorUserID != nil {
		t.Errorf("ActorUserID must be nil for pre-sync denial, got %q (not a valid UUID)", *captured.ActorUserID)
	}
	if reason, _ := captured.Metadata.(map[string]any)["reason"].(string); reason != "email_link_to_admin" {
		t.Errorf("reason in metadata = %q, want email_link_to_admin", reason)
	}
}

// mockPreflightSyncer for wouldBeAdmin tests.
type mockPreflightSyncer struct {
	bySubject map[string]*domain.User
	byEmail   map[string]*domain.User
}

func (m *mockPreflightSyncer) GetBySubject(_ context.Context, _, subject string) (*domain.User, error) {
	u := m.bySubject[subject]
	if u == nil {
		return nil, sql.ErrNoRows
	}
	return u, nil
}
func (m *mockPreflightSyncer) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	u := m.byEmail[email]
	if u == nil {
		return nil, sql.ErrNoRows
	}
	return u, nil
}

// captureAuditRecorder captures the last recorded event.
type captureAuditRecorder struct {
	capture **adminaudit.Event
}

func (c *captureAuditRecorder) Record(_ context.Context, ev adminaudit.Event) {
	*c.capture = &ev
}

// ---------------------------------------------------------------------------
// Default AMR values test
// ---------------------------------------------------------------------------

// TestDefaultAMRValues_CoverCommonIdPs verifies the default AMR set covers
// Okta, Azure AD, Google Workspace, and hardware key authentication.
func TestDefaultAMRValues_CoverCommonIdPs(t *testing.T) {
	// Default set hard-coded in FromAppConfig when OIDC_MFA_AMR_VALUES is empty.
	defaults := []string{"mfa", "otp", "hwk", "swk"}
	cfg := &Config{MFAAMRValues: defaults}

	cases := []struct {
		name  string
		amr   []string
		wants bool
	}{
		{"okta (mfa+pwd)", []string{"mfa", "pwd"}, true},
		{"azure ad (mfa)", []string{"mfa"}, true},
		{"google workspace (otp)", []string{"otp"}, true},
		{"fido2 hardware key (hwk)", []string{"hwk"}, true},
		{"software key (swk)", []string{"swk"}, true},
		{"password only", []string{"pwd"}, false},
		{"no amr", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cfg.CheckMFAClaims(IDTokenClaims{AMR: tc.amr})
			if got != tc.wants {
				t.Errorf("CheckMFAClaims(amr=%v) = %v, want %v", tc.amr, got, tc.wants)
			}
		})
	}
}

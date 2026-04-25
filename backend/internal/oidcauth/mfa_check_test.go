//go:build enterprise

package oidcauth

import (
	"testing"
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

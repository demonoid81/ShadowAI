package auth

import (
	"net/http/httptest"
	"testing"
)

// TestExtractGovernanceContext_DepartmentFromJWT — department must come from
// JWT claims only (trusted). Request headers must NOT override it.
func TestExtractGovernanceContext_DepartmentFromJWT(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	// Attempt to inject department via header — must be ignored.
	r.Header.Set("X-Department", "attacker-dept")

	claims := &Claims{Department: "finance"}
	gctx := ExtractGovernanceContext(r, claims)
	if gctx.Department != "finance" {
		t.Errorf("Department = %q, want 'finance' (from JWT)", gctx.Department)
	}
}

// TestExtractGovernanceContext_HeaderNotUsedForDepartment verifies that
// X-Department header is silently ignored (no spoofing vector).
func TestExtractGovernanceContext_HeaderNotUsedForDepartment(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("X-Department", "legal")

	// No JWT claims (or claims with empty department).
	gctx := ExtractGovernanceContext(r, &Claims{Department: ""})
	if gctx.Department == "legal" {
		t.Error("X-Department header must NOT populate Department (spoofing vector)")
	}
	if gctx.Department != "" {
		t.Errorf("empty claims.Department → empty GovernanceContext.Department, got %q", gctx.Department)
	}
}

// TestExtractGovernanceContext_NilClaims — nil claims → empty department.
func TestExtractGovernanceContext_NilClaims(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	gctx := ExtractGovernanceContext(r, nil)
	if gctx.Department != "" {
		t.Errorf("nil claims → empty department, got %q", gctx.Department)
	}
}

// TestExtractGovernanceContext_SensitivityValid — valid header values are preserved.
func TestExtractGovernanceContext_SensitivityValid(t *testing.T) {
	cases := []string{"standard", "confidential", "restricted"}
	for _, s := range cases {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("X-Data-Sensitivity", s)
		gctx := ExtractGovernanceContext(r, nil)
		if gctx.Sensitivity != s {
			t.Errorf("X-Data-Sensitivity=%q → Sensitivity=%q, want %q", s, gctx.Sensitivity, s)
		}
	}
}

// TestExtractGovernanceContext_SensitivityMissing — absent header → "unknown"
// (fail-restrictive: not "standard").
func TestExtractGovernanceContext_SensitivityMissing(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	gctx := ExtractGovernanceContext(r, nil)
	if gctx.Sensitivity != SensitivityUnknown {
		t.Errorf("missing header → Sensitivity=%q, want %q (fail-restrictive default)", gctx.Sensitivity, SensitivityUnknown)
	}
}

// TestExtractGovernanceContext_SensitivityInvalid — unrecognised value → "unknown".
func TestExtractGovernanceContext_SensitivityInvalid(t *testing.T) {
	cases := []string{"public", "top-secret", "HIGH", "1", ""}
	for _, s := range cases {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("X-Data-Sensitivity", s)
		gctx := ExtractGovernanceContext(r, nil)
		if gctx.Sensitivity != SensitivityUnknown {
			t.Errorf("invalid sensitivity %q → Sensitivity=%q, want %q", s, gctx.Sensitivity, SensitivityUnknown)
		}
	}
}

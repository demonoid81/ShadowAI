package auth

import (
	"context"
	"time"
	"testing"

	"github.com/shadowai/backend/internal/domain"
)

// panicSafe calls f and swallows any panic.
// Used to call repository methods whose mutation-before-INSERT logic we want
// to verify without a real database (nil *sql.DB panics on ExecContext, but
// the struct mutation happens before that call).
func panicSafe(f func()) {
	defer func() { recover() }()
	f()
}

// ---------------------------------------------------------------------------
// Repository: CreateUser, CreateUserSCIM, CreateUserOIDC
// Regression: returned domain.User must have OrgID set after create.
// ---------------------------------------------------------------------------

func TestCreateUser_OrgID_DefaultedWhenEmpty(t *testing.T) {
	r := &Repository{} // nil db — panics at ExecContext, after the mutation
	u := &domain.User{ID: "uid-1", Email: "a@b.com", Role: "user", APIKey: "key-1"}

	panicSafe(func() { _ = r.CreateUser(context.Background(), u) })

	if u.OrgID != domain.DefaultOrgID {
		t.Errorf("OrgID = %q, want %q", u.OrgID, domain.DefaultOrgID)
	}
}

func TestCreateUser_OrgID_ExplicitPreserved(t *testing.T) {
	r := &Repository{}
	const customOrg = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	u := &domain.User{ID: "uid-2", Email: "a@b.com", Role: "user", APIKey: "key-2", OrgID: customOrg}

	panicSafe(func() { _ = r.CreateUser(context.Background(), u) })

	if u.OrgID != customOrg {
		t.Errorf("OrgID = %q, want %q", u.OrgID, customOrg)
	}
}

func TestCreateUserSCIM_OrgID_DefaultedWhenEmpty(t *testing.T) {
	r := &Repository{}
	ext := "scim-ext-123"
	u := &domain.User{ID: "uid-3", Email: "scim@b.com", Role: "user",
		IsActive: true, SCIMExternalID: &ext}

	panicSafe(func() { _ = r.CreateUserSCIM(context.Background(), u) })

	if u.OrgID != domain.DefaultOrgID {
		t.Errorf("OrgID = %q, want %q", u.OrgID, domain.DefaultOrgID)
	}
}

func TestCreateUserSCIM_OrgID_ExplicitPreserved(t *testing.T) {
	r := &Repository{}
	const customOrg = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
	ext := "scim-ext-456"
	u := &domain.User{ID: "uid-4", Email: "scim@b.com", Role: "user",
		IsActive: true, SCIMExternalID: &ext, OrgID: customOrg}

	panicSafe(func() { _ = r.CreateUserSCIM(context.Background(), u) })

	if u.OrgID != customOrg {
		t.Errorf("OrgID = %q, want %q", u.OrgID, customOrg)
	}
}

func TestCreateUserOIDC_OrgID_DefaultedWhenEmpty(t *testing.T) {
	r := &Repository{}
	issuer, subject := "https://idp.example.com", "sub-123"
	now := time.Now()
	u := &domain.User{
		ID: "uid-5", Email: "oidc@b.com", Role: "user",
		OIDCIssuer: &issuer, OIDCSubject: &subject, LastOIDCLoginAt: &now,
	}

	panicSafe(func() { _ = r.CreateUserOIDC(context.Background(), u) })

	if u.OrgID != domain.DefaultOrgID {
		t.Errorf("OrgID = %q, want %q", u.OrgID, domain.DefaultOrgID)
	}
}

func TestCreateUserOIDC_OrgID_ExplicitPreserved(t *testing.T) {
	r := &Repository{}
	const customOrg = "cccccccc-dddd-eeee-ffff-000000000000"
	issuer, subject := "https://idp.example.com", "sub-456"
	now := time.Now()
	u := &domain.User{
		ID: "uid-6", Email: "oidc@b.com", Role: "user",
		OIDCIssuer: &issuer, OIDCSubject: &subject, LastOIDCLoginAt: &now,
		OrgID: customOrg,
	}

	panicSafe(func() { _ = r.CreateUserOIDC(context.Background(), u) })

	if u.OrgID != customOrg {
		t.Errorf("OrgID = %q, want %q", u.OrgID, customOrg)
	}
}

// ---------------------------------------------------------------------------
// Service: generateToken includes OrgID in JWT claims.
// ---------------------------------------------------------------------------

func TestGenerateToken_OrgID_IncludedInClaims(t *testing.T) {
	svc := newTestService()
	u := &domain.User{
		ID: "user-7", Email: "tok@b.com", Role: "user",
		OrgID: "org-abc-123", TokenVersion: 0,
	}
	tokenStr, err := svc.generateToken(u)
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	got, err := svc.ValidateToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if got.OrgID != "org-abc-123" {
		t.Errorf("Claims.OrgID = %q, want %q", got.OrgID, "org-abc-123")
	}
}

func TestGenerateToken_OrgID_DefaultsWhenEmpty(t *testing.T) {
	svc := newTestService()
	u := &domain.User{ID: "user-8", Email: "tok2@b.com", Role: "user"} // OrgID empty

	tokenStr, err := svc.generateToken(u)
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	got, err := svc.ValidateToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if got.OrgID != domain.DefaultOrgID {
		t.Errorf("Claims.OrgID = %q, want %q", got.OrgID, domain.DefaultOrgID)
	}
}

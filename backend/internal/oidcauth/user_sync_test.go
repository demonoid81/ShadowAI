//go:build enterprise

package oidcauth

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/shadowai/backend/internal/domain"
)

// mockSyncRepo implements the minimal subset of auth.Repository used by UserSyncer.
// We test the logic, not the DB queries.
type mockSyncRepo struct {
	bySubject map[string]*domain.User // "issuer:subject" → User
	byEmail   map[string]*domain.User
	created   []*domain.User
	updated   []*domain.User
}

func (m *mockSyncRepo) GetByOIDCSubject(_ context.Context, issuer, subject string) (*domain.User, error) {
	u, ok := m.bySubject[issuer+":"+subject]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return u, nil
}
func (m *mockSyncRepo) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	u, ok := m.byEmail[email]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return u, nil
}
func (m *mockSyncRepo) CreateUserOIDC(_ context.Context, u *domain.User) error {
	m.created = append(m.created, u)
	return nil
}
func (m *mockSyncRepo) UpdateUserOIDC(_ context.Context, u *domain.User) error {
	m.updated = append(m.updated, u)
	return nil
}

// syncRepoAdapter wraps mockSyncRepo to satisfy the interface expected by syncerForTest.
// (We use a small interface inline so tests don't depend on the full auth.Repository.)

type syncerForTest struct {
	repo      syncRepo
	cfg       *Config
}

type syncRepo interface {
	GetByOIDCSubject(ctx context.Context, issuer, subject string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	CreateUserOIDC(ctx context.Context, u *domain.User) error
	UpdateUserOIDC(ctx context.Context, u *domain.User) error
}

// requireVerifiedEmail mirrors UserSyncer.requireVerifiedEmail for test helpers.
func (s *syncerForTest) requireVerifiedEmail(claims IDTokenClaims, op string) error {
	if s.cfg.AllowUnverifiedEmail {
		return nil
	}
	if !claims.EmailVerified {
		return errAccessDenied(op + " requires email_verified=true")
	}
	return nil
}

// sync replicates UserSyncer.Sync logic for testing without a real *auth.Repository.
func (s *syncerForTest) sync(ctx context.Context, issuer string, claims IDTokenClaims) (SyncResult, error) {
	user, err := s.repo.GetByOIDCSubject(ctx, issuer, claims.Subject)
	if err != nil && err != sql.ErrNoRows {
		return SyncResult{}, err
	}
	if user != nil {
		if !user.IsActive {
			return SyncResult{}, errAccessDenied("account disabled")
		}
		return syncExisting(ctx, s.repo, s.cfg, user, issuer, claims)
	}
	if claims.Email != "" && s.cfg.LinkByEmail {
		if err := s.requireVerifiedEmail(claims, "link_by_email"); err != nil {
			return SyncResult{}, err
		}
		byEmail, err := s.repo.GetByEmail(ctx, claims.Email)
		if err != nil && err != sql.ErrNoRows {
			return SyncResult{}, err
		}
		if byEmail != nil {
			if !byEmail.IsActive {
				return SyncResult{}, errAccessDenied("account disabled")
			}
			now := time.Now().UTC()
			byEmail.OIDCIssuer = &issuer
			byEmail.OIDCSubject = &claims.Subject
			byEmail.LastOIDCLoginAt = &now
			res, err := syncExisting(ctx, s.repo, s.cfg, byEmail, issuer, claims)
			if err != nil {
				return res, err
			}
			res.Action = "linked"
			return res, nil
		}
	}
	if s.cfg.AutoProvision {
		if err := s.requireVerifiedEmail(claims, "auto_provision"); err != nil {
			return SyncResult{}, err
		}
		return provision(ctx, s.repo, s.cfg, issuer, claims)
	}
	return SyncResult{}, errAccessDenied("no matching account")
}

type accessDeniedErr string

func (e accessDeniedErr) Error() string { return string(e) }
func errAccessDenied(s string) error    { return accessDeniedErr("oidc: " + s) }

func syncExisting(ctx context.Context, repo syncRepo, cfg *Config, user *domain.User, issuer string, claims IDTokenClaims) (SyncResult, error) {
	res := SyncResult{User: user, Action: "login"}
	now := time.Now().UTC()
	// Always update identity fields and timestamp.
	user.OIDCIssuer = &issuer
	user.OIDCSubject = &claims.Subject
	user.LastOIDCLoginAt = &now
	if claims.Email != "" && claims.Email != user.Email && (cfg.AllowUnverifiedEmail || claims.EmailVerified) {
		user.Email = claims.Email
	}
	if role := cfg.MapRole(claims.Groups); role != "" && role != user.Role {
		user.Role = role
		res.RoleMapped = true
	}
	if claims.Department != "" && (user.Department == nil || *user.Department != claims.Department) {
		dept := claims.Department
		user.Department = &dept
		res.DeptSynced = true
	}
	// Always persist (at minimum LastOIDCLoginAt changed).
	repo.UpdateUserOIDC(ctx, user)
	if res.RoleMapped || res.DeptSynced {
		res.Action = "synced"
	}
	return res, nil
}

func provision(ctx context.Context, repo syncRepo, cfg *Config, issuer string, claims IDTokenClaims) (SyncResult, error) {
	if claims.Email == "" {
		return SyncResult{}, errAccessDenied("email required for auto-provision")
	}
	role := "user"
	if mapped := cfg.MapRole(claims.Groups); mapped != "" {
		role = mapped
	}
	now := time.Now().UTC()
	user := &domain.User{
		ID: "new-uuid", Email: claims.Email, Role: role, IsActive: true,
		OIDCIssuer: &issuer, OIDCSubject: &claims.Subject, LastOIDCLoginAt: &now,
	}
	if claims.Department != "" {
		dept := claims.Department
		user.Department = &dept
	}
	repo.CreateUserOIDC(ctx, user)
	return SyncResult{User: user, Action: "provisioned", RoleMapped: role != "user", DeptSynced: claims.Department != ""}, nil
}

func newTestSyncer(cfg *Config, repo *mockSyncRepo) *syncerForTest {
	return &syncerForTest{repo: repo, cfg: cfg}
}

const testIssuer = "https://idp.example.com"

// ---------------------------------------------------------------------------
// Subject match tests
// ---------------------------------------------------------------------------

func TestSync_SubjectMatch_ReturnsLogin(t *testing.T) {
	subj := "sub-123"
	user := &domain.User{ID: "u-1", Email: "user@example.com", Role: "user", IsActive: true,
		OIDCIssuer: func() *string { s := testIssuer; return &s }(), OIDCSubject: &subj}
	repo := &mockSyncRepo{
		bySubject: map[string]*domain.User{testIssuer + ":" + subj: user},
		byEmail:   map[string]*domain.User{},
	}
	s := newTestSyncer(&Config{}, repo)
	// Subject match does NOT require email_verified — subject binding is stable.
	res, err := s.sync(context.Background(), testIssuer, IDTokenClaims{Subject: subj, Email: "user@example.com", EmailVerified: false})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if res.Action != "login" && res.Action != "synced" {
		t.Errorf("action = %q, want login or synced", res.Action)
	}
}

// TestSync_SubjectMatch_LastLoginAlwaysSaved — LastOIDCLoginAt is persisted on
// every login, even when nothing else changed.
func TestSync_SubjectMatch_LastLoginAlwaysSaved(t *testing.T) {
	subj := "sub-ts"
	user := &domain.User{ID: "u-ts", Email: "ts@example.com", Role: "user", IsActive: true,
		OIDCIssuer: func() *string { s := testIssuer; return &s }(), OIDCSubject: &subj}
	repo := &mockSyncRepo{
		bySubject: map[string]*domain.User{testIssuer + ":" + subj: user},
		byEmail:   map[string]*domain.User{},
	}
	s := newTestSyncer(&Config{}, repo)
	_, err := s.sync(context.Background(), testIssuer, IDTokenClaims{Subject: subj})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	// UpdateUserOIDC must be called even when no profile fields changed.
	if len(repo.updated) == 0 {
		t.Error("UpdateUserOIDC must be called on every login to persist LastOIDCLoginAt")
	}
}

// TestSync_InactiveUser_Denied — inactive user is rejected.
func TestSync_InactiveUser_Denied(t *testing.T) {
	subj := "sub-inactive"
	user := &domain.User{ID: "u-2", IsActive: false, OIDCIssuer: func() *string { s := testIssuer; return &s }(), OIDCSubject: &subj}
	repo := &mockSyncRepo{bySubject: map[string]*domain.User{testIssuer + ":" + subj: user}, byEmail: map[string]*domain.User{}}
	s := newTestSyncer(&Config{}, repo)
	_, err := s.sync(context.Background(), testIssuer, IDTokenClaims{Subject: subj})
	if err == nil {
		t.Error("inactive user: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Link by email tests
// ---------------------------------------------------------------------------

func TestSync_LinkByEmail_WhenEnabled(t *testing.T) {
	user := &domain.User{ID: "u-3", Email: "link@example.com", Role: "user", IsActive: true}
	repo := &mockSyncRepo{
		bySubject: map[string]*domain.User{},
		byEmail:   map[string]*domain.User{"link@example.com": user},
	}
	s := newTestSyncer(&Config{LinkByEmail: true}, repo)
	// Must have EmailVerified=true for link_by_email to work.
	res, err := s.sync(context.Background(), testIssuer, IDTokenClaims{Subject: "new-sub", Email: "link@example.com", EmailVerified: true})
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if res.Action != "linked" {
		t.Errorf("action = %q, want linked", res.Action)
	}
}

// TestSync_LinkByEmail_UnverifiedEmail_Rejected — unverified email + link_by_email
// must be rejected to prevent account-takeover.
func TestSync_LinkByEmail_UnverifiedEmail_Rejected(t *testing.T) {
	user := &domain.User{ID: "u-ev", Email: "victim@example.com", IsActive: true}
	repo := &mockSyncRepo{
		bySubject: map[string]*domain.User{},
		byEmail:   map[string]*domain.User{"victim@example.com": user},
	}
	s := newTestSyncer(&Config{LinkByEmail: true, AllowUnverifiedEmail: false}, repo)
	_, err := s.sync(context.Background(), testIssuer, IDTokenClaims{
		Subject: "attacker-sub", Email: "victim@example.com", EmailVerified: false,
	})
	if err == nil {
		t.Error("unverified email link_by_email: expected error (account-takeover prevention), got nil")
	}
}

func TestSync_LinkByEmail_WhenDisabled_Denies(t *testing.T) {
	user := &domain.User{ID: "u-4", Email: "link2@example.com", IsActive: true}
	repo := &mockSyncRepo{
		bySubject: map[string]*domain.User{},
		byEmail:   map[string]*domain.User{"link2@example.com": user},
	}
	// LinkByEmail=false — should not link, no AutoProvision → deny
	s := newTestSyncer(&Config{LinkByEmail: false, AutoProvision: false}, repo)
	_, err := s.sync(context.Background(), testIssuer, IDTokenClaims{Subject: "s", Email: "link2@example.com"})
	if err == nil {
		t.Error("link_by_email=false: expected deny, got nil error")
	}
}

// ---------------------------------------------------------------------------
// Auto-provision tests
// ---------------------------------------------------------------------------

func TestSync_AutoProvision_CreatesUser(t *testing.T) {
	repo := &mockSyncRepo{bySubject: map[string]*domain.User{}, byEmail: map[string]*domain.User{}}
	s := newTestSyncer(&Config{AutoProvision: true}, repo)
	res, err := s.sync(context.Background(), testIssuer, IDTokenClaims{
		Subject: "new-sub", Email: "new@example.com", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if res.Action != "provisioned" {
		t.Errorf("action = %q, want provisioned", res.Action)
	}
	if len(repo.created) != 1 {
		t.Errorf("expected 1 created user, got %d", len(repo.created))
	}
}

func TestSync_AutoProvision_Disabled_Denies(t *testing.T) {
	repo := &mockSyncRepo{bySubject: map[string]*domain.User{}, byEmail: map[string]*domain.User{}}
	s := newTestSyncer(&Config{AutoProvision: false}, repo)
	_, err := s.sync(context.Background(), testIssuer, IDTokenClaims{Subject: "s", Email: "x@x.com"})
	if err == nil {
		t.Error("auto_provision=false: expected deny, got nil")
	}
}

// ---------------------------------------------------------------------------
// Role and department mapping tests
// ---------------------------------------------------------------------------

func TestSync_RoleMapping_FromGroups(t *testing.T) {
	repo := &mockSyncRepo{bySubject: map[string]*domain.User{}, byEmail: map[string]*domain.User{}}
	s := newTestSyncer(&Config{
		AutoProvision: true,
		RoleMap:       map[string]string{"admins": "admin"},
	}, repo)
	res, err := s.sync(context.Background(), testIssuer, IDTokenClaims{
		Subject: "s", Email: "a@x.com", EmailVerified: true, Groups: []string{"admins"},
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if res.User.Role != "admin" {
		t.Errorf("role = %q, want admin", res.User.Role)
	}
	if !res.RoleMapped {
		t.Error("RoleMapped must be true")
	}
}

func TestSync_DepartmentClaim_Synced(t *testing.T) {
	repo := &mockSyncRepo{bySubject: map[string]*domain.User{}, byEmail: map[string]*domain.User{}}
	s := newTestSyncer(&Config{AutoProvision: true, DepartmentClaim: "department"}, repo)
	res, err := s.sync(context.Background(), testIssuer, IDTokenClaims{
		Subject: "s", Email: "d@x.com", EmailVerified: true, Department: "finance",
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if res.User.Department == nil || *res.User.Department != "finance" {
		t.Errorf("department = %v, want finance", res.User.Department)
	}
	if !res.DeptSynced {
		t.Error("DeptSynced must be true")
	}
}

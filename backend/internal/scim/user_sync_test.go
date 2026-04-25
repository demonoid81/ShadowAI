//go:build enterprise

package scim

import (
	"context"
	"database/sql"
	"testing"

	"github.com/shadowai/backend/internal/domain"
)

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

type mockSCIMRepo struct {
	byExternalID map[string]*domain.User
	byEmail      map[string]*domain.User
	byID         map[string]*domain.User
	created      []*domain.User
	updated      []*domain.User
}

func (m *mockSCIMRepo) GetBySCIMExternalID(_ context.Context, id string) (*domain.User, error) {
	if u, ok := m.byExternalID[id]; ok { return u, nil }
	return nil, sql.ErrNoRows
}
func (m *mockSCIMRepo) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	if u, ok := m.byEmail[email]; ok { return u, nil }
	return nil, sql.ErrNoRows
}
func (m *mockSCIMRepo) GetByID(_ context.Context, id string) (*domain.User, error) {
	if u, ok := m.byID[id]; ok { return u, nil }
	return nil, sql.ErrNoRows
}
func (m *mockSCIMRepo) CreateUserSCIM(_ context.Context, u *domain.User) error {
	m.created = append(m.created, u)
	if m.byID == nil { m.byID = make(map[string]*domain.User) }
	m.byID[u.ID] = u
	return nil
}
func (m *mockSCIMRepo) UpdateUserSCIM(_ context.Context, u *domain.User) error {
	m.updated = append(m.updated, u)
	if m.byID == nil { m.byID = make(map[string]*domain.User) }
	m.byID[u.ID] = u
	return nil
}
func (m *mockSCIMRepo) ListUsersSCIM(_ context.Context) ([]domain.User, error) {
	var users []domain.User
	for _, u := range m.byID { users = append(users, *u) }
	return users, nil
}

func newSyncer(repo *mockSCIMRepo) *UserSyncer {
	cfg, _ := ParseSyncConfig("user", `{"admins":"admin"}`, "", false)
	return NewUserSyncer(repo, cfg)
}

// ---------------------------------------------------------------------------
// Provision tests
// ---------------------------------------------------------------------------

func TestProvision_NewUser_Created(t *testing.T) {
	repo := &mockSCIMRepo{
		byExternalID: map[string]*domain.User{},
		byEmail:      map[string]*domain.User{},
	}
	s := newSyncer(repo)
	result, err := s.Provision(context.Background(), User{
		ExternalID: "ext-001",
		UserName:   "user@example.com",
		Active:     true,
		Roles:      []RoleValue{{Value: "user"}},
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if result.Action != "provisioned" {
		t.Errorf("action = %q, want provisioned", result.Action)
	}
	if len(repo.created) != 1 {
		t.Errorf("expected 1 created user, got %d", len(repo.created))
	}
}

func TestProvision_ExistingExternalID_Updated(t *testing.T) {
	existing := &domain.User{ID: "u-1", Email: "old@example.com", Role: "user", IsActive: true}
	extID := "ext-002"
	existing.SCIMExternalID = &extID
	repo := &mockSCIMRepo{
		byExternalID: map[string]*domain.User{"ext-002": existing},
		byEmail:      map[string]*domain.User{},
		byID:         map[string]*domain.User{"u-1": existing},
	}
	s := newSyncer(repo)
	result, err := s.Provision(context.Background(), User{
		ExternalID: "ext-002",
		UserName:   "new@example.com",
		Active:     true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if result.Action != "updated" {
		t.Errorf("action = %q, want updated", result.Action)
	}
	if result.User.Email != "new@example.com" {
		t.Errorf("email = %q, want new@example.com", result.User.Email)
	}
}

func TestProvision_RoleMapping_FromRoles(t *testing.T) {
	repo := &mockSCIMRepo{
		byExternalID: map[string]*domain.User{},
		byEmail:      map[string]*domain.User{},
	}
	s := newSyncer(repo)
	result, err := s.Provision(context.Background(), User{
		UserName: "admin@example.com",
		Active:   true,
		Roles:    []RoleValue{{Value: "admins"}}, // mapped to "admin" via roleMap
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if result.User.Role != "admin" {
		t.Errorf("role = %q, want admin", result.User.Role)
	}
}

func TestProvision_DepartmentFromEnterpriseExtension(t *testing.T) {
	repo := &mockSCIMRepo{
		byExternalID: map[string]*domain.User{},
		byEmail:      map[string]*domain.User{},
	}
	s := newSyncer(repo)
	result, err := s.Provision(context.Background(), User{
		UserName: "emp@example.com",
		Active:   true,
		EnterpriseUser: &EnterpriseUser{Department: "Finance"},
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if result.User.Department == nil || *result.User.Department != "Finance" {
		t.Errorf("department = %v, want Finance", result.User.Department)
	}
}

func TestProvision_MissingEmail_SCIMError(t *testing.T) {
	repo := &mockSCIMRepo{byExternalID: map[string]*domain.User{}, byEmail: map[string]*domain.User{}}
	s := newSyncer(repo)
	_, err := s.Provision(context.Background(), User{Active: true})
	if err == nil {
		t.Error("expected error for missing email/userName, got nil")
	}
	var scimErr *SCIMError
	if !isSCIMError(err, &scimErr) || scimErr.Status != 400 {
		t.Errorf("expected SCIM 400 error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Deprovision tests
// ---------------------------------------------------------------------------

func TestDeprovision_SetsInactive(t *testing.T) {
	u := &domain.User{ID: "u-dp", Email: "dp@example.com", IsActive: true}
	repo := &mockSCIMRepo{byID: map[string]*domain.User{"u-dp": u}}
	s := newSyncer(repo)
	result, err := s.Deprovision(context.Background(), "u-dp")
	if err != nil {
		t.Fatalf("Deprovision: %v", err)
	}
	if result.Action != "deprovisioned" {
		t.Errorf("action = %q, want deprovisioned", result.Action)
	}
	if result.User.IsActive {
		t.Error("user must be inactive after deprovision")
	}
}

func TestDeprovision_NotFound_SCIMError(t *testing.T) {
	repo := &mockSCIMRepo{byID: map[string]*domain.User{}}
	s := newSyncer(repo)
	_, err := s.Deprovision(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected 404 error for nonexistent user, got nil")
	}
	var scimErr *SCIMError
	if !isSCIMError(err, &scimErr) || scimErr.Status != 404 {
		t.Errorf("expected SCIM 404, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// PATCH tests
// ---------------------------------------------------------------------------

func TestPatch_ActiveFalse_Deprovisioned(t *testing.T) {
	u := &domain.User{ID: "u-p", Email: "p@example.com", IsActive: true}
	repo := &mockSCIMRepo{byID: map[string]*domain.User{"u-p": u}}
	s := newSyncer(repo)
	result, err := s.ApplyPatch(context.Background(), "u-p", PatchRequest{
		Operations: []PatchOp{{Op: "Replace", Path: "active", Value: false}},
	})
	if err != nil {
		t.Fatalf("ApplyPatch: %v", err)
	}
	if result.Action != "deprovisioned" {
		t.Errorf("action = %q, want deprovisioned", result.Action)
	}
}

func TestPatch_ActiveTrue_Reactivated(t *testing.T) {
	u := &domain.User{ID: "u-r", Email: "r@example.com", IsActive: false}
	repo := &mockSCIMRepo{byID: map[string]*domain.User{"u-r": u}}
	s := newSyncer(repo)
	result, err := s.ApplyPatch(context.Background(), "u-r", PatchRequest{
		Operations: []PatchOp{{Op: "Replace", Path: "active", Value: true}},
	})
	if err != nil {
		t.Fatalf("ApplyPatch: %v", err)
	}
	if result.Action != "reactivated" {
		t.Errorf("action = %q, want reactivated", result.Action)
	}
}

// ---------------------------------------------------------------------------
// ParseSyncConfig tests
// ---------------------------------------------------------------------------

func TestParseSyncConfig_InvalidRole(t *testing.T) {
	_, err := ParseSyncConfig("superadmin", "", "", false)
	if err == nil {
		t.Error("expected error for invalid default role, got nil")
	}
}

func TestParseSyncConfig_InvalidRoleMapJSON(t *testing.T) {
	_, err := ParseSyncConfig("user", "{invalid", "", false)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// ---------------------------------------------------------------------------
// Filter tests
// ---------------------------------------------------------------------------

func TestApplyFilter_UserName(t *testing.T) {
	users := []domain.User{
		{ID: "1", Email: "alice@example.com"},
		{ID: "2", Email: "bob@example.com"},
	}
	got := applyFilter(users, `userName eq "alice@example.com"`)
	if len(got) != 1 || got[0].ID != "1" {
		t.Errorf("filter userName: got %v", got)
	}
}

func TestApplyFilter_ExternalID(t *testing.T) {
	extID := "ext-xyz"
	users := []domain.User{
		{ID: "1", SCIMExternalID: &extID},
		{ID: "2"},
	}
	got := applyFilter(users, `externalId eq "ext-xyz"`)
	if len(got) != 1 || got[0].ID != "1" {
		t.Errorf("filter externalId: got %v", got)
	}
}

// isSCIMError is a type assertion helper.
func isSCIMError(err error, target **SCIMError) bool {
	if e, ok := err.(*SCIMError); ok {
		*target = e
		return true
	}
	return false
}

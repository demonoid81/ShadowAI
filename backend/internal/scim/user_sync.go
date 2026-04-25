//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package scim

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/domain"
)

// SyncConfig holds SCIM provisioning config.
type SyncConfig struct {
	DefaultRole         string
	RoleMap             map[string]string // SCIM role/group → ShadowAI role
	DepartmentAttribute string            // unused: we read from EnterpriseUser.Department
	LinkByEmail         bool
}

// ParseSyncConfig builds a SyncConfig from config values.
func ParseSyncConfig(defaultRole, roleMapJSON, deptAttr string, linkByEmail bool) (*SyncConfig, error) {
	if defaultRole == "" {
		defaultRole = auth.RoleUser
	}
	if _, err := auth.NormalizeRole(defaultRole); err != nil {
		return nil, fmt.Errorf("scim: invalid SCIM_PROVISION_DEFAULT_ROLE %q", defaultRole)
	}
	roleMap := make(map[string]string)
	if roleMapJSON != "" {
		if err := json.Unmarshal([]byte(roleMapJSON), &roleMap); err != nil {
			return nil, fmt.Errorf("scim: invalid SCIM_ROLE_MAP_JSON: %w", err)
		}
		// Validate all target roles eagerly — a typo in env should fail startup.
		for scimGroup, targetRole := range roleMap {
			if _, err := auth.NormalizeRole(targetRole); err != nil {
				return nil, fmt.Errorf("scim: SCIM_ROLE_MAP_JSON value %q for key %q is not a valid ShadowAI role", targetRole, scimGroup)
			}
		}
	}
	return &SyncConfig{
		DefaultRole:         defaultRole,
		RoleMap:             roleMap,
		DepartmentAttribute: deptAttr,
		LinkByEmail:         linkByEmail,
	}, nil
}

// mapRole returns the ShadowAI role for a SCIM user's roles/groups.
func (c *SyncConfig) mapRole(roles []RoleValue) string {
	for _, r := range roles {
		for _, key := range []string{r.Value, r.Display} {
			if role, ok := c.roleMap(key); ok {
				return role
			}
		}
	}
	return c.DefaultRole
}

func (c *SyncConfig) roleMap(key string) (string, bool) {
	for k, v := range c.RoleMap {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// SCIMRepo is the subset of auth.Repository used by SCIM sync.
type SCIMRepo interface {
	GetBySCIMExternalID(ctx context.Context, externalID string) (*domain.User, error)
	GetBySCIMExternalIDInOrg(ctx context.Context, externalID, orgID string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByEmailInOrg(ctx context.Context, email, orgID string) (*domain.User, error)
	GetByIDScoped(ctx context.Context, id, orgID string) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*domain.User, error)
	CreateUserSCIM(ctx context.Context, u *domain.User) error
	UpdateUserSCIM(ctx context.Context, u *domain.User) error
	ListUsersSCIM(ctx context.Context) ([]domain.User, error)
}

// SyncResult describes what happened during a SCIM sync operation.
type SyncResult struct {
	User   *domain.User
	Action string // "provisioned" | "updated" | "deprovisioned" | "reactivated" | "linked"
}

// UserSyncer translates SCIM operations into domain.User changes.
// orgID is the org this syncer is authorized to manage (from SCIM Bearer token config).
// Empty orgID means default org (single-tenant / legacy path).
type UserSyncer struct {
	repo   SCIMRepo
	cfg    *SyncConfig
	orgID  string
}

// NewUserSyncer creates a UserSyncer.
func NewUserSyncer(repo SCIMRepo, cfg *SyncConfig) *UserSyncer {
	return &UserSyncer{repo: repo, cfg: cfg}
}

// WithOrgID returns a UserSyncer copy scoped to the given org.
func (s *UserSyncer) WithOrgID(orgID string) *UserSyncer {
	c := *s
	c.orgID = orgID
	return &c
}

// Provision creates or updates a user from a SCIM POST/PUT request.
func (s *UserSyncer) Provision(ctx context.Context, scimUser User) (SyncResult, error) {
	email := primaryEmail(scimUser)
	if email == "" && scimUser.UserName != "" {
		email = scimUser.UserName
	}
	if email == "" {
		return SyncResult{}, &SCIMError{Status: 400, Detail: "userName or primary email is required", ScimType: "invalidValue"}
	}

	// 1. ExternalID match — org-scoped to prevent cross-tenant ID collision.
	if scimUser.ExternalID != "" {
		var existing *domain.User
		var err error
		if s.orgID != "" {
			existing, err = s.repo.GetBySCIMExternalIDInOrg(ctx, scimUser.ExternalID, s.orgID)
		} else {
			existing, err = s.repo.GetBySCIMExternalID(ctx, scimUser.ExternalID)
		}
		if err != nil && err != sql.ErrNoRows {
			return SyncResult{}, err
		}
		if existing != nil {
			return s.updateExisting(ctx, existing, scimUser, email)
		}
	}

	// 2. Email link — org-scoped to prevent cross-tenant account merge (RFC D6.1).
	if s.cfg.LinkByEmail && email != "" {
		var byEmail *domain.User
		var err error
		if s.orgID != "" {
			byEmail, err = s.repo.GetByEmailInOrg(ctx, email, s.orgID)
		} else {
			byEmail, err = s.repo.GetByEmail(ctx, email)
		}
		if err != nil && err != sql.ErrNoRows {
			return SyncResult{}, err
		}
		if byEmail != nil {
			// Identity conflict: email matches but the existing user is already
			// linked to a DIFFERENT SCIM external ID. Silently updating would
			// merge two separate IdP identities into one account — reject.
			if byEmail.SCIMExternalID != nil && *byEmail.SCIMExternalID != "" &&
				scimUser.ExternalID != "" && *byEmail.SCIMExternalID != scimUser.ExternalID {
				return SyncResult{}, &SCIMError{
					Status:   409,
					Detail:   fmt.Sprintf("email %q is already linked to a different SCIM identity (externalId conflict)", email),
					ScimType: "uniqueness",
				}
			}
			action := "linked"
			if byEmail.SCIMExternalID == nil && scimUser.ExternalID != "" {
				extID := scimUser.ExternalID
				byEmail.SCIMExternalID = &extID
			}
			res, err := s.updateExisting(ctx, byEmail, scimUser, email)
			if err != nil {
				return res, err
			}
			res.Action = action
			return res, nil
		}
	}

	// 3. Provision new user.
	role := s.cfg.mapRole(scimUser.Roles)
	dept := departmentValue(scimUser)
	extID := scimUser.ExternalID

	u := &domain.User{
		ID:       uuid.NewString(),
		Email:    email,
		Role:     role,
		OrgID:    s.orgID,
		IsActive: boolVal(scimUser.Active, true), // default true for new users
	}
	if dept != "" {
		u.Department = &dept
	}
	if extID != "" {
		u.SCIMExternalID = &extID
	}
	if err := s.repo.CreateUserSCIM(ctx, u); err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			return SyncResult{}, &SCIMError{Status: 409, Detail: "email already exists", ScimType: "uniqueness"}
		}
		return SyncResult{}, err
	}
	return SyncResult{User: u, Action: "provisioned"}, nil
}

// Deprovision sets IsActive=false for the user. Per SCIM spec, DELETE does not
// permanently remove the user — it deactivates them.
func (s *UserSyncer) Deprovision(ctx context.Context, userID string) (SyncResult, error) {
	u, err := s.scopedGetByID(ctx, userID)
	if err == sql.ErrNoRows {
		return SyncResult{}, &SCIMError{Status: 404, Detail: "user not found"}
	}
	if err != nil {
		return SyncResult{}, err
	}
	if !u.IsActive {
		return SyncResult{User: u, Action: "already_deprovisioned"}, nil
	}
	u.IsActive = false
	if err := s.repo.UpdateUserSCIM(ctx, u); err != nil {
		return SyncResult{}, err
	}
	return SyncResult{User: u, Action: "deprovisioned"}, nil
}

// scopedGetByID uses GetByIDScoped when orgID is set, otherwise GetByID.
func (s *UserSyncer) scopedGetByID(ctx context.Context, id string) (*domain.User, error) {
	if s.orgID != "" {
		return s.repo.GetByIDScoped(ctx, id, s.orgID)
	}
	return s.repo.GetByID(ctx, id)
}

// ApplyPatch applies a SCIM PATCH request to the user.
func (s *UserSyncer) ApplyPatch(ctx context.Context, userID string, req PatchRequest) (SyncResult, error) {
	u, err := s.scopedGetByID(ctx, userID)
	if err == sql.ErrNoRows {
		return SyncResult{}, &SCIMError{Status: 404, Detail: "user not found"}
	}
	if err != nil {
		return SyncResult{}, err
	}

	wasActive := u.IsActive
	for _, op := range req.Operations {
		if err := applyOp(u, op); err != nil {
			return SyncResult{}, &SCIMError{Status: 400, Detail: err.Error(), ScimType: "invalidValue"}
		}
	}

	if err := s.repo.UpdateUserSCIM(ctx, u); err != nil {
		return SyncResult{}, err
	}

	action := "updated"
	if wasActive && !u.IsActive {
		action = "deprovisioned"
	} else if !wasActive && u.IsActive {
		action = "reactivated"
	}
	return SyncResult{User: u, Action: action}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (s *UserSyncer) updateExisting(ctx context.Context, u *domain.User, scimUser User, email string) (SyncResult, error) {
	wasActive := u.IsActive
	u.Email = email
	// PUT is a full replace per SCIM RFC 7644 §3.5.1.
	// Active omitted (nil) defaults to true — an omitted field in a full replace
	// means "reset to default", not "no change". This intentionally reactivates
	// a previously deprovisioned user if the IdP sends a full PUT without active=false.
	// Operators who only want to change specific fields should use PATCH instead.
	u.IsActive = boolVal(scimUser.Active, true)
	if len(scimUser.Roles) > 0 {
		u.Role = s.cfg.mapRole(scimUser.Roles)
	}
	if dept := departmentValue(scimUser); dept != "" {
		u.Department = &dept
	}
	if scimUser.ExternalID != "" {
		extID := scimUser.ExternalID
		u.SCIMExternalID = &extID
	}
	if err := s.repo.UpdateUserSCIM(ctx, u); err != nil {
		return SyncResult{}, err
	}
	action := "updated"
	if wasActive && !u.IsActive {
		action = "deprovisioned"
	} else if !wasActive && u.IsActive {
		action = "reactivated"
	}
	return SyncResult{User: u, Action: action}, nil
}

func applyOp(u *domain.User, op PatchOp) error {
	opLower := strings.ToLower(op.Op)
	path := strings.ToLower(strings.TrimSpace(op.Path))

	switch {
	case path == "active" || path == "":
		// Try to extract active from value map.
		if m, ok := op.Value.(map[string]any); ok {
			if v, ok := m["active"].(bool); ok {
				u.IsActive = v
				return nil
			}
		}
		if v, ok := op.Value.(bool); ok {
			u.IsActive = v
			return nil
		}
	case strings.Contains(path, "email"):
		if opLower == "replace" || opLower == "add" {
			if s, ok := op.Value.(string); ok {
				u.Email = s
			}
		}
	case strings.Contains(path, "role"):
		if s, ok := op.Value.(string); ok {
			if normalized, err := auth.NormalizeRole(s); err == nil {
				u.Role = normalized
			}
		}
	case strings.Contains(path, "department"):
		if s, ok := op.Value.(string); ok {
			u.Department = &s
		}
	}
	return nil
}

func primaryEmail(u User) string {
	for _, e := range u.Emails {
		if e.Primary {
			return e.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return ""
}

func departmentValue(u User) string {
	if u.EnterpriseUser != nil {
		return u.EnterpriseUser.Department
	}
	return ""
}

// SCIMError is a SCIM-spec error that maps to an HTTP status code.
type SCIMError struct {
	Status   int
	Detail   string
	ScimType string
}

func (e *SCIMError) Error() string { return fmt.Sprintf("scim %d: %s", e.Status, e.Detail) }

package auth

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/shadowai/backend/internal/domain"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateUser(ctx context.Context, u *domain.User) error {
	orgID := u.OrgID
	if orgID == "" {
		orgID = domain.DefaultOrgID
	}
	u.OrgID = orgID
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password, role, api_key, is_active, token_version, org_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		u.ID, u.Email, u.Password, u.Role, u.APIKey, u.IsActive, u.TokenVersion, orgID)
	return err
}

func (r *Repository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRowContext(ctx,
		`SELECT id, email, password, role, department, COALESCE(api_key,'') AS api_key, is_active, token_version,
		        totp_secret, mfa_required, scim_external_id, created_at, updated_at,
		        COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001') AS org_id
		 FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.Password, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion,
			&u.TOTPSecret, &u.MFARequired, &u.SCIMExternalID, &u.CreatedAt, &u.UpdatedAt, &u.OrgID)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *Repository) GetByAPIKey(ctx context.Context, apiKey string) (*domain.User, error) {
	return r.getByAPIKey(ctx, apiKey)
}

func (r *Repository) GetByAPIKeyHash(ctx context.Context, apiKeyHash string) (*domain.User, error) {
	return r.getByAPIKey(ctx, apiKeyHash)
}

func (r *Repository) getByAPIKey(ctx context.Context, apiKey string) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRowContext(ctx,
		`SELECT id, email, password, role, department, COALESCE(api_key,'') AS api_key, is_active, token_version,
		        totp_secret, mfa_required, scim_external_id, created_at, updated_at,
		        COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001') AS org_id
		 FROM users WHERE api_key = $1 AND is_active = true`, apiKey).
		Scan(&u.ID, &u.Email, &u.Password, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion,
			&u.TOTPSecret, &u.MFARequired, &u.SCIMExternalID, &u.CreatedAt, &u.UpdatedAt, &u.OrgID)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *Repository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRowContext(ctx,
		`SELECT id, email, password, role, department, COALESCE(api_key,'') AS api_key, is_active, token_version,
		        totp_secret, mfa_required, scim_external_id, created_at, updated_at,
		        COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001') AS org_id
		 FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.Password, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion,
			&u.TOTPSecret, &u.MFARequired, &u.SCIMExternalID, &u.CreatedAt, &u.UpdatedAt, &u.OrgID)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *Repository) ListUsers(ctx context.Context, orgID string) ([]domain.User, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if orgID == "" {
		rows, err = r.db.QueryContext(ctx,
			`SELECT id, email, role, department, COALESCE(api_key,'') AS api_key, is_active, token_version, created_at, updated_at,
			        COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001') AS org_id
			 FROM users ORDER BY created_at DESC`)
	} else {
		rows, err = r.db.QueryContext(ctx,
			`SELECT id, email, role, department, COALESCE(api_key,'') AS api_key, is_active, token_version, created_at, updated_at,
			        COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001') AS org_id
			 FROM users WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []domain.User
	for rows.Next() {
		var u domain.User
		if err := rows.Scan(&u.ID, &u.Email, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion, &u.CreatedAt, &u.UpdatedAt, &u.OrgID); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// GetByIDScoped looks up a user by id within the given org.
// Used for admin endpoints; returns sql.ErrNoRows when user exists but belongs to a different org.
func (r *Repository) GetByIDScoped(ctx context.Context, id, orgID string) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRowContext(ctx,
		`SELECT id, email, password, role, department, COALESCE(api_key,'') AS api_key, is_active, token_version,
		        totp_secret, mfa_required, scim_external_id, created_at, updated_at,
		        COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001') AS org_id
		 FROM users WHERE id = $1 AND org_id = $2`, id, orgID).
		Scan(&u.ID, &u.Email, &u.Password, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion,
			&u.TOTPSecret, &u.MFARequired, &u.SCIMExternalID, &u.CreatedAt, &u.UpdatedAt, &u.OrgID)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// UpdateUserScoped updates user fields with org ownership check (AND org_id=$N).
func (r *Repository) UpdateUserScoped(ctx context.Context, u *domain.User, orgID string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET email=$1, role=$2, is_active=$3, department=$4, updated_at=now() WHERE id=$5 AND org_id=$6`,
		u.Email, u.Role, u.IsActive, u.Department, u.ID, orgID)
	return err
}

// CountUsersByOrg returns the number of users in the given org.
func (r *Repository) CountUsersByOrg(ctx context.Context, orgID string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE org_id = $1`, orgID).Scan(&count)
	return count, err
}

func (r *Repository) UpdateUser(ctx context.Context, u *domain.User) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET email=$1, role=$2, is_active=$3, department=$4, updated_at=now() WHERE id=$5`,
		u.Email, u.Role, u.IsActive, u.Department, u.ID)
	return err
}

func (r *Repository) UpdateAPIKeyHash(ctx context.Context, userID, hashedAPIKey string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET api_key=$1, updated_at=now() WHERE id=$2`,
		hashedAPIKey, userID)
	return err
}

func (r *Repository) IncrementTokenVersion(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET token_version = token_version + 1, updated_at=now() WHERE id=$1`,
		userID)
	return err
}

func (r *Repository) CountUsers(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

// ---------------------------------------------------------------------------
// PR-E2: SCIM repository methods.
// ---------------------------------------------------------------------------

// GetBySCIMExternalID looks up a user by scim_external_id.
// Returns (nil, sql.ErrNoRows) if not found.
func (r *Repository) GetBySCIMExternalID(ctx context.Context, externalID string) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRowContext(ctx,
		`SELECT id, email, password, role, department, COALESCE(api_key,'') AS api_key, is_active, token_version,
		        totp_secret, mfa_required, scim_external_id, created_at, updated_at,
		        COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001') AS org_id
		 FROM users WHERE scim_external_id = $1`, externalID).
		Scan(&u.ID, &u.Email, &u.Password, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion,
			&u.TOTPSecret, &u.MFARequired, &u.SCIMExternalID, &u.CreatedAt, &u.UpdatedAt, &u.OrgID)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// CreateUserSCIM inserts a SCIM-provisioned user. Password is empty (IdP-only auth).
func (r *Repository) CreateUserSCIM(ctx context.Context, u *domain.User) error {
	orgID := u.OrgID
	if orgID == "" {
		orgID = domain.DefaultOrgID
	}
	u.OrgID = orgID
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password, role, department, is_active, token_version, scim_external_id, org_id)
		 VALUES ($1, $2, '', $3, $4, $5, 0, $6, $7)`,
		u.ID, u.Email, u.Role, u.Department, u.IsActive, u.SCIMExternalID, orgID)
	return err
}

// UpdateUserSCIM updates SCIM-synced fields. Does not touch password or api_key.
// Bumps token_version when IsActive changes (forces re-login after deprovisioning).
func (r *Repository) UpdateUserSCIM(ctx context.Context, u *domain.User) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users
		 SET email=$1, role=$2, department=$3, is_active=$4, scim_external_id=$5,
		     token_version = CASE WHEN is_active != $4 THEN token_version + 1 ELSE token_version END,
		     updated_at=now()
		 WHERE id=$6`,
		u.Email, u.Role, u.Department, u.IsActive, u.SCIMExternalID, u.ID)
	return err
}

// ListUsersSCIM returns all users for SCIM list operations.
func (r *Repository) ListUsersSCIM(ctx context.Context) ([]domain.User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, email, role, department, is_active, scim_external_id, created_at, updated_at,
		        COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001') AS org_id
		 FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []domain.User
	for rows.Next() {
		var u domain.User
		if err := rows.Scan(&u.ID, &u.Email, &u.Role, &u.Department, &u.IsActive,
			&u.SCIMExternalID, &u.CreatedAt, &u.UpdatedAt, &u.OrgID); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// ---------------------------------------------------------------------------
// PR-E1.1: MFA repository methods.
// ---------------------------------------------------------------------------

// SetTOTPSecret stores the encrypted TOTP secret, enables MFA, and bumps token_version.
// Bumping token_version invalidates all existing JWT and API-key sessions, forcing the
// user to re-authenticate with MFA from this point on.
// Returns an error if no row was updated (e.g. caller's UserID doesn't exist in DB).
func (r *Repository) SetTOTPSecret(ctx context.Context, userID, encryptedSecret string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE users
		 SET totp_secret=$1, mfa_required=true,
		     token_version = token_version + 1,
		     updated_at=now()
		 WHERE id=$2`,
		encryptedSecret, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("set_totp: user %q not found", userID)
	}
	return nil
}

// ClearTOTPSecret removes the TOTP secret and disables MFA for the user.
// Returns an error if no row was updated.
func (r *Repository) ClearTOTPSecret(ctx context.Context, userID string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE users SET totp_secret=NULL, mfa_required=false, updated_at=now() WHERE id=$1`,
		userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("clear_totp: user %q not found", userID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// PR-E1: OIDC identity repository methods.
// ---------------------------------------------------------------------------

// GetByOIDCSubject looks up a user by (oidc_issuer, oidc_subject).
// Returns (nil, sql.ErrNoRows) if not found.
func (r *Repository) GetByOIDCSubject(ctx context.Context, issuer, subject string) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRowContext(ctx,
		`SELECT id, email, password, role, department, COALESCE(api_key,'') AS api_key, is_active, token_version,
		        oidc_issuer, oidc_subject, last_oidc_login_at, created_at, updated_at,
		        COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001') AS org_id
		 FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2`,
		issuer, subject).Scan(
		&u.ID, &u.Email, &u.Password, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion,
		&u.OIDCIssuer, &u.OIDCSubject, &u.LastOIDCLoginAt, &u.CreatedAt, &u.UpdatedAt, &u.OrgID,
	)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// CreateUserOIDC inserts a new user created via OIDC auto-provision.
// Password is intentionally empty (OIDC users authenticate via IdP only).
// api_key is NULL — users.api_key has a UNIQUE constraint; inserting '' would collide
// with any other empty-string API key (including a second OIDC-provisioned user).
func (r *Repository) CreateUserOIDC(ctx context.Context, u *domain.User) error {
	orgID := u.OrgID
	if orgID == "" {
		orgID = domain.DefaultOrgID
	}
	u.OrgID = orgID
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password, role, department, is_active, token_version,
		                   oidc_issuer, oidc_subject, last_oidc_login_at, org_id)
		 VALUES ($1, $2, '', $3, $4, true, 0, $5, $6, $7, $8)`,
		u.ID, u.Email, u.Role, u.Department, u.OIDCIssuer, u.OIDCSubject, u.LastOIDCLoginAt, orgID)
	return err
}

// UpdateUserOIDC updates OIDC identity fields + synced profile fields (email, role, department)
// and the last_oidc_login_at timestamp. Called on every successful OIDC login.
// Note: token_version is NOT incremented here. If role changed the caller is responsible
// for deciding whether to invalidate sessions (rare in practice — role changes require
// re-login naturally via token expiry).
func (r *Repository) UpdateUserOIDC(ctx context.Context, u *domain.User) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users
		 SET email=$1, role=$2, department=$3,
		     oidc_issuer=$4, oidc_subject=$5, last_oidc_login_at=$6,
		     updated_at=now()
		 WHERE id=$7`,
		u.Email, u.Role, u.Department,
		u.OIDCIssuer, u.OIDCSubject, u.LastOIDCLoginAt,
		u.ID)
	return err
}

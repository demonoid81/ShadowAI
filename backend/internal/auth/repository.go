package auth

import (
	"context"
	"database/sql"

	"github.com/shadowai/backend/internal/domain"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateUser(ctx context.Context, u *domain.User) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password, role, api_key, is_active, token_version) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		u.ID, u.Email, u.Password, u.Role, u.APIKey, u.IsActive, u.TokenVersion)
	return err
}

func (r *Repository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRowContext(ctx,
		`SELECT id, email, password, role, department, api_key, is_active, token_version,
		        totp_secret, mfa_required, created_at, updated_at FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.Password, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion,
			&u.TOTPSecret, &u.MFARequired, &u.CreatedAt, &u.UpdatedAt)
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
		`SELECT id, email, password, role, department, api_key, is_active, token_version,
		        totp_secret, mfa_required, created_at, updated_at FROM users WHERE api_key = $1 AND is_active = true`, apiKey).
		Scan(&u.ID, &u.Email, &u.Password, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion,
			&u.TOTPSecret, &u.MFARequired, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *Repository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRowContext(ctx,
		`SELECT id, email, password, role, department, api_key, is_active, token_version,
		        totp_secret, mfa_required, created_at, updated_at FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.Password, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion,
			&u.TOTPSecret, &u.MFARequired, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *Repository) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, email, role, department, api_key, is_active, token_version, created_at, updated_at FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []domain.User
	for rows.Next() {
		var u domain.User
		if err := rows.Scan(&u.ID, &u.Email, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
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
// PR-E1.1: MFA repository methods.
// ---------------------------------------------------------------------------

// SetTOTPSecret stores the encrypted TOTP secret, enables MFA, and bumps token_version.
// Bumping token_version invalidates all existing JWT and API-key sessions, forcing the
// user to re-authenticate with MFA from this point on.
func (r *Repository) SetTOTPSecret(ctx context.Context, userID, encryptedSecret string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users
		 SET totp_secret=$1, mfa_required=true,
		     token_version = token_version + 1,
		     updated_at=now()
		 WHERE id=$2`,
		encryptedSecret, userID)
	return err
}

// ClearTOTPSecret removes the TOTP secret and disables MFA for the user.
func (r *Repository) ClearTOTPSecret(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET totp_secret=NULL, mfa_required=false, updated_at=now() WHERE id=$1`,
		userID)
	return err
}

// ---------------------------------------------------------------------------
// PR-E1: OIDC identity repository methods.
// ---------------------------------------------------------------------------

// GetByOIDCSubject looks up a user by (oidc_issuer, oidc_subject).
// Returns (nil, sql.ErrNoRows) if not found.
func (r *Repository) GetByOIDCSubject(ctx context.Context, issuer, subject string) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRowContext(ctx,
		`SELECT id, email, password, role, department, api_key, is_active, token_version,
		        oidc_issuer, oidc_subject, last_oidc_login_at, created_at, updated_at
		 FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2`,
		issuer, subject).Scan(
		&u.ID, &u.Email, &u.Password, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion,
		&u.OIDCIssuer, &u.OIDCSubject, &u.LastOIDCLoginAt, &u.CreatedAt, &u.UpdatedAt,
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
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password, role, department, is_active, token_version,
		                   oidc_issuer, oidc_subject, last_oidc_login_at)
		 VALUES ($1, $2, '', $3, $4, true, 0, $5, $6, $7)`,
		u.ID, u.Email, u.Role, u.Department, u.OIDCIssuer, u.OIDCSubject, u.LastOIDCLoginAt)
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

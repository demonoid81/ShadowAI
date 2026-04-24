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
		`SELECT id, email, password, role, department, api_key, is_active, token_version, created_at, updated_at FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.Password, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion, &u.CreatedAt, &u.UpdatedAt)
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
		`SELECT id, email, password, role, department, api_key, is_active, token_version, created_at, updated_at FROM users WHERE api_key = $1 AND is_active = true`, apiKey).
		Scan(&u.ID, &u.Email, &u.Password, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *Repository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRowContext(ctx,
		`SELECT id, email, password, role, department, api_key, is_active, token_version, created_at, updated_at FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.Password, &u.Role, &u.Department, &u.APIKey, &u.IsActive, &u.TokenVersion, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *Repository) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, email, role, api_key, is_active, token_version, created_at, updated_at FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []domain.User
	for rows.Next() {
		var u domain.User
		if err := rows.Scan(&u.ID, &u.Email, &u.Role, &u.APIKey, &u.IsActive, &u.TokenVersion, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (r *Repository) UpdateUser(ctx context.Context, u *domain.User) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET email=$1, role=$2, is_active=$3, updated_at=now() WHERE id=$4`,
		u.Email, u.Role, u.IsActive, u.ID)
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

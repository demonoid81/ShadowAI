//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// PR-T2.6: org management and SCIM token registry repository.

package orgadmin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/shadowai/backend/internal/domain"
)

// Repository handles organizations and scim_tokens tables.
type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// ---------------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------------

func (r *Repository) ListOrgs(ctx context.Context) ([]domain.Organization, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, slug, is_active, created_at, updated_at
		 FROM organizations ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list orgs: %w", err)
	}
	defer rows.Close()
	var orgs []domain.Organization
	for rows.Next() {
		var o domain.Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.IsActive, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	return orgs, rows.Err()
}

func (r *Repository) GetOrgByID(ctx context.Context, id string) (*domain.Organization, error) {
	var o domain.Organization
	err := r.db.QueryRowContext(ctx,
		`SELECT id, name, slug, is_active, created_at, updated_at
		 FROM organizations WHERE id = $1`, id).
		Scan(&o.ID, &o.Name, &o.Slug, &o.IsActive, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func (r *Repository) CreateOrg(ctx context.Context, o *domain.Organization) error {
	return r.db.QueryRowContext(ctx,
		`INSERT INTO organizations (id, name, slug, is_active)
		 VALUES ($1, $2, $3, $4)
		 RETURNING created_at, updated_at`,
		o.ID, o.Name, o.Slug, o.IsActive).
		Scan(&o.CreatedAt, &o.UpdatedAt)
}

func (r *Repository) UpdateOrg(ctx context.Context, o *domain.Organization) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE organizations SET name=$1, slug=$2, is_active=$3, updated_at=now()
		 WHERE id=$4`,
		o.Name, o.Slug, o.IsActive, o.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ---------------------------------------------------------------------------
// SCIM tokens
// ---------------------------------------------------------------------------

// SCIMTokenCreateResult carries the plaintext token (returned once, never stored).
type SCIMTokenCreateResult struct {
	Token       *domain.SCIMToken
	PlainToken  string // returned once; caller must transmit to operator and discard
}

func (r *Repository) ListSCIMTokens(ctx context.Context, orgID string) ([]domain.SCIMToken, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, org_id, label, is_active, created_at, last_used_at
		 FROM scim_tokens WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list scim tokens: %w", err)
	}
	defer rows.Close()
	var tokens []domain.SCIMToken
	for rows.Next() {
		var t domain.SCIMToken
		var label sql.NullString
		if err := rows.Scan(&t.ID, &t.OrgID, &label, &t.IsActive, &t.CreatedAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		if label.Valid {
			t.Label = label.String
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// CreateSCIMToken generates a secure random token, hashes it, and inserts into DB.
// Returns the record + plaintext token (the only time it's visible).
func (r *Repository) CreateSCIMToken(ctx context.Context, orgID, label string) (*SCIMTokenCreateResult, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	plain := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plain))
	hash := hex.EncodeToString(sum[:])

	var t domain.SCIMToken
	var lbl sql.NullString
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO scim_tokens (org_id, token_hash, label)
		 VALUES ($1, $2, $3)
		 RETURNING id, org_id, label, is_active, created_at, last_used_at`,
		orgID, hash, label).
		Scan(&t.ID, &t.OrgID, &lbl, &t.IsActive, &t.CreatedAt, &t.LastUsedAt)
	if err != nil {
		return nil, fmt.Errorf("create scim token: %w", err)
	}
	if lbl.Valid {
		t.Label = lbl.String
	}
	return &SCIMTokenCreateResult{Token: &t, PlainToken: plain}, nil
}

// RevokeSCIMToken sets is_active=false (soft revoke — audit trail preserved).
func (r *Repository) RevokeSCIMToken(ctx context.Context, tokenID, orgID string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE scim_tokens SET is_active=false WHERE id=$1 AND org_id=$2`,
		tokenID, orgID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

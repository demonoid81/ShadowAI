//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// PR-T2.3.2: scim_tokens repository for per-request bearer token → org resolution.

package scim

import (
	"context"
	"database/sql"
	"errors"
)

// SCIMTokensRepository looks up org_id from the scim_tokens table.
type SCIMTokensRepository struct {
	db *sql.DB
}

// NewSCIMTokensRepository creates a token resolver backed by the scim_tokens table.
func NewSCIMTokensRepository(db *sql.DB) *SCIMTokensRepository {
	return &SCIMTokensRepository{db: db}
}

// GetOrgByTokenHash returns the org_id for an active token identified by its
// SHA-256 hex hash. Returns ("", sql.ErrNoRows) when not found.
func (r *SCIMTokensRepository) GetOrgByTokenHash(ctx context.Context, tokenHash string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("scim_tokens: repo not configured")
	}
	var orgID string
	err := r.db.QueryRowContext(ctx,
		`SELECT org_id FROM scim_tokens WHERE token_hash = $1 AND is_active = true LIMIT 1`,
		tokenHash).Scan(&orgID)
	if err != nil {
		return "", err
	}
	return orgID, nil
}

package domain

import "time"

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Password     string    `json:"-"`
	Role         string    `json:"role"`
	// Department is used by PR-G3 context_scoped governance routing.
	// Nullable — set by admin or IdP sync. Empty = no department assigned.
	Department   *string   `json:"department,omitempty"`
	APIKey       string    `json:"api_key,omitempty"`
	IsActive     bool      `json:"is_active"`
	TokenVersion int       `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	// PR-E1: OIDC identity. Set after first OIDC login or admin linking.
	OIDCIssuer      *string   `json:"oidc_issuer,omitempty"`
	OIDCSubject     *string   `json:"oidc_subject,omitempty"`
	LastOIDCLoginAt *time.Time `json:"last_oidc_login_at,omitempty"`
}

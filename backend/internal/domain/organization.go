package domain

import "time"

// Organization represents a tenant org.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SCIMToken is an org-scoped SCIM Bearer token registration.
// Plaintext token is never stored — only SHA-256 hex hash.
type SCIMToken struct {
	ID          string     `json:"id"`
	OrgID       string     `json:"org_id"`
	Label       string     `json:"label,omitempty"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

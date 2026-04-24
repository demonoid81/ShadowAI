//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package oidcauth

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/domain"
)

// IDTokenClaims holds the fields we extract from the OIDC ID token.
type IDTokenClaims struct {
	Subject    string   // "sub" claim — IdP-assigned user identifier
	Email      string   // "email" claim
	Name       string   // "name" claim (optional)
	Groups     []string // "groups" claim — for role mapping
	Department string   // extracted via Config.DepartmentClaim
}

// UserSyncer resolves an OIDC identity to a ShadowAI user, applying
// link/provision/sync rules.
type UserSyncer struct {
	repo   *auth.Repository
	cfg    *Config
	authSvc *auth.Service
}

// NewUserSyncer creates a UserSyncer.
func NewUserSyncer(repo *auth.Repository, cfg *Config, authSvc *auth.Service) *UserSyncer {
	return &UserSyncer{repo: repo, cfg: cfg, authSvc: authSvc}
}

// SyncResult carries the outcome of an OIDC sync.
type SyncResult struct {
	User          *domain.User
	Action        string // "login" | "provisioned" | "linked" | "synced"
	RoleMapped    bool   // true if role was set from OIDC groups claim
	DeptSynced    bool   // true if department was updated from IdP claim
}

// Sync resolves the OIDC claims to a ShadowAI user according to config:
//
//  1. Subject match → sync email/role/department; issue JWT.
//  2. No subject + existing email → link only if LinkByEmail=true.
//  3. No user → create only if AutoProvision=true.
//  4. Inactive user → reject.
func (s *UserSyncer) Sync(ctx context.Context, issuer string, claims IDTokenClaims) (SyncResult, error) {
	// 1. Subject match.
	user, err := s.repo.GetByOIDCSubject(ctx, issuer, claims.Subject)
	if err != nil && err != sql.ErrNoRows {
		return SyncResult{}, fmt.Errorf("oidc sync: subject lookup: %w", err)
	}
	if user != nil {
		if !user.IsActive {
			return SyncResult{}, fmt.Errorf("oidc: account disabled")
		}
		return s.syncExisting(ctx, user, issuer, claims)
	}

	// 2. Email link (if configured).
	if claims.Email != "" && s.cfg.LinkByEmail {
		byEmail, err := s.repo.GetByEmail(ctx, claims.Email)
		if err != nil && err != sql.ErrNoRows {
			return SyncResult{}, fmt.Errorf("oidc sync: email lookup: %w", err)
		}
		if byEmail != nil {
			if !byEmail.IsActive {
				return SyncResult{}, fmt.Errorf("oidc: account disabled")
			}
			// Link OIDC identity to the existing account.
			now := time.Now().UTC()
			byEmail.OIDCIssuer = &issuer
			byEmail.OIDCSubject = &claims.Subject
			byEmail.LastOIDCLoginAt = &now
			res, err := s.syncExisting(ctx, byEmail, issuer, claims)
			if err != nil {
				return res, err
			}
			res.Action = "linked"
			return res, nil
		}
	}

	// 3. Auto-provision.
	if s.cfg.AutoProvision {
		return s.provision(ctx, issuer, claims)
	}

	return SyncResult{}, fmt.Errorf("oidc: no matching account (auto_provision=false, link_by_email=%v)", s.cfg.LinkByEmail)
}

// syncExisting updates an existing user's fields from OIDC claims.
func (s *UserSyncer) syncExisting(ctx context.Context, user *domain.User, issuer string, claims IDTokenClaims) (SyncResult, error) {
	res := SyncResult{User: user, Action: "login"}
	changed := false

	// Update OIDC identity if needed (e.g. first link or subject refresh).
	now := time.Now().UTC()
	if user.OIDCIssuer == nil || *user.OIDCIssuer != issuer {
		user.OIDCIssuer = &issuer
		changed = true
	}
	if user.OIDCSubject == nil || *user.OIDCSubject != claims.Subject {
		user.OIDCSubject = &claims.Subject
		changed = true
	}
	user.LastOIDCLoginAt = &now

	// Sync email from IdP (authoritative source).
	if claims.Email != "" && claims.Email != user.Email {
		user.Email = claims.Email
		changed = true
	}

	// Sync role from groups claim.
	if role := s.cfg.MapRole(claims.Groups); role != "" {
		normalized, _ := auth.NormalizeRole(role)
		if normalized != "" && normalized != user.Role {
			user.Role = normalized
			res.RoleMapped = true
			changed = true
		}
	}

	// Sync department from IdP claim.
	if claims.Department != "" {
		if user.Department == nil || *user.Department != claims.Department {
			dept := claims.Department
			user.Department = &dept
			res.DeptSynced = true
			changed = true
		}
	}

	if changed {
		if err := s.repo.UpdateUserOIDC(ctx, user); err != nil {
			return res, fmt.Errorf("oidc sync: update user: %w", err)
		}
		res.Action = "synced"
	}
	return res, nil
}

// provision creates a new user from OIDC claims.
func (s *UserSyncer) provision(ctx context.Context, issuer string, claims IDTokenClaims) (SyncResult, error) {
	if claims.Email == "" {
		return SyncResult{}, fmt.Errorf("oidc provision: email claim required for auto-provision")
	}

	role := auth.RoleUser
	if mapped := s.cfg.MapRole(claims.Groups); mapped != "" {
		if normalized, _ := auth.NormalizeRole(mapped); normalized != "" {
			role = normalized
		}
	}

	now := time.Now().UTC()
	user := &domain.User{
		ID:              uuid.NewString(),
		Email:           claims.Email,
		Role:            role,
		IsActive:        true,
		OIDCIssuer:      &issuer,
		OIDCSubject:     &claims.Subject,
		LastOIDCLoginAt: &now,
	}
	if claims.Department != "" {
		dept := claims.Department
		user.Department = &dept
	}

	if err := s.repo.CreateUserOIDC(ctx, user); err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return SyncResult{}, fmt.Errorf("oidc provision: email already exists (race condition)")
		}
		return SyncResult{}, fmt.Errorf("oidc provision: %w", err)
	}
	return SyncResult{User: user, Action: "provisioned", RoleMapped: role != auth.RoleUser, DeptSynced: claims.Department != ""}, nil
}

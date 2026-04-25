package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/adminaudit"
)

type contextKey string

const claimsKey contextKey = "claims"

func GetClaims(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey).(*Claims)
	return c
}

// WithClaims встраивает Claims в context. Используется при тестировании
// handler'ов в обход AuthMiddleware.
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}

func (s *Service) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var claims *Claims

		unauthorized := func() {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		}
		mfaRequired := func() {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"mfa_required"}`, http.StatusUnauthorized)
		}

		// Try JWT from Authorization header
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			c, err := s.ValidateToken(tokenStr)
			if err != nil {
				unauthorized()
				return
			}

			// PR-E1.1 Fix 1: break-glass tokens have no DB row.
			// Trust the JWT signature alone; no GetByID needed.
			if c.BreakGlass {
				claims = c
			} else {
				user, err := s.repo.GetByID(r.Context(), c.UserID)
				if err != nil || !user.IsActive {
					unauthorized()
					return
				}
				if c.TokenVersion != user.TokenVersion {
					unauthorized()
					return
				}
				// Refresh from DB — JWT payload is not source of truth for mutable fields.
				c.Role = user.Role
				c.Email = user.Email
				c.OrgID = user.OrgID
				c.TokenVersion = user.TokenVersion
				c.Department = ptrStr(user.Department)

				// PR-E1.1 Fix 2: enforce MFA for users where mfa_required=true.
				if user.MFARequired && !c.MFAVerified {
					mfaRequired()
					return
				}
				claims = c
			}
		}

		// Try API key
		if claims == nil {
			apiKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
			if apiKey != "" {
				u, err := s.GetUserByAPIKey(r.Context(), apiKey)
				if err == nil {
					if !u.IsActive {
						unauthorized()
						return
					}
					// PR-E1.1 Fix 2: API-key sessions don't carry MFAVerified.
					// If the user requires MFA, API-key access is blocked.
					if u.MFARequired {
						mfaRequired()
						return
					}
					orgID := u.OrgID
					if orgID == "" {
						orgID = "00000000-0000-0000-0000-000000000001"
					}
					claims = &Claims{
						UserID:       u.ID,
						Email:        u.Email,
						Role:         u.Role,
						OrgID:        orgID,
						Department:   ptrStr(u.Department),
						TokenVersion: u.TokenVersion,
					}
				}
			}
		}

		if claims == nil {
			unauthorized()
			return
		}

		// PR-T2.2: Fail-closed for missing org.
		// Non-break-glass sessions without an org are rejected.
		// Note: repository reads use COALESCE(org_id, default), so legacy/NULL rows
		// are mapped to the default org before reaching here — they will NOT be
		// rejected. This check catches cases where org resolution was skipped
		// entirely (e.g. a future code path that builds Claims without a DB lookup).
		// Break-glass is explicitly global (OrgID="" is valid when BreakGlass=true).
		if claims.OrgID == "" && !claims.BreakGlass {
			unauthorized()
			return
		}

		// PR-E1.1 Fix 3: ADMIN_MFA_REQUIRED enforces MFA for all admin sessions
		// regardless of per-user mfa_required flag.
		// Break-glass sessions are exempt (emergency access by definition).
		//
		// Enrollment exception: if the admin hasn't enrolled yet (mfa_required=false),
		// allow access to /auth/mfa/setup and /auth/mfa/confirm only, so they can
		// enroll without being permanently locked out. All other routes are blocked
		// until enrollment is complete.
		if s.adminMFARequired && claims.Role == RoleAdmin && !claims.MFAVerified && !claims.BreakGlass {
			if !isMFAEnrollmentPath(r.URL.Path) {
				mfaRequired()
				return
			}
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		// PR-T2.3.1: inject orgID for adminaudit package (avoids auth↔adminaudit cycle).
		ctx = adminaudit.SetOrgContext(ctx, claims.OrgID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// isMFAEnrollmentPath returns true for the two MFA enrollment routes.
// These are the only routes a non-enrolled admin can access when
// ADMIN_MFA_REQUIRED=true and the admin hasn't completed MFA yet.
func isMFAEnrollmentPath(path string) bool {
	return strings.HasSuffix(path, "/auth/mfa/setup") ||
		strings.HasSuffix(path, "/auth/mfa/confirm")
}

// ptrStr dereferences a nullable string pointer for use in Claims.
// nil (department not assigned) becomes empty string.
func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// RequireGlobalAdmin allows only global_admin role or break-glass sessions.
// Break-glass is accepted as emergency path; audit metadata carries break_glass=true.
func RequireGlobalAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if claims.Role != RoleGlobalAdmin && !claims.BreakGlass {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"forbidden: global_admin role required"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireOrgAccess allows global_admin/break-glass to access any org,
// and admin to access only their own org (from URL param orgIDParam).
func RequireOrgAccess(orgIDParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if IsGlobalClaims(claims) {
				next.ServeHTTP(w, r)
				return
			}
			if claims.Role != RoleAdmin {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			// Tenant admin: may only access their own org.
			targetOrgID := mux.Vars(r)[orgIDParam]
			if targetOrgID != "" && targetOrgID != claims.OrgID {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"forbidden: cross-org access denied"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			for _, role := range roles {
				if claims.Role == role {
					next.ServeHTTP(w, r)
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		})
	}
}

// RequireAdminOrSelf allows admins always, or users operating on their own resource.
func RequireAdminOrSelf(pathParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			if claims.Role == "admin" {
				next.ServeHTTP(w, r)
				return
			}

			userID := mux.Vars(r)[pathParam]
			if userID == "" || userID != claims.UserID {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

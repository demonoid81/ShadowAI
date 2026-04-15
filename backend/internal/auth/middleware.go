package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

type contextKey string

const claimsKey contextKey = "claims"

func GetClaims(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey).(*Claims)
	return c
}

func (s *Service) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var claims *Claims

		unauthorized := func() {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
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
			user, err := s.repo.GetByID(r.Context(), c.UserID)
			if err != nil || !user.IsActive {
				unauthorized()
				return
			}
			if c.TokenVersion != user.TokenVersion {
				unauthorized()
				return
			}
			c.Role = user.Role
			c.Email = user.Email
			c.TokenVersion = user.TokenVersion
			claims = c
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
					claims = &Claims{
						UserID:       u.ID,
						Email:        u.Email,
						Role:         u.Role,
						TokenVersion: u.TokenVersion,
					}
				}
			}
		}

		if claims == nil {
			unauthorized()
			return
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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

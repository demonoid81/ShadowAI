//go:build !enterprise

// Core-build stub: MFA is an enterprise-only feature.
// In core build, IssueMFAChallenge and generateMFAToken are no-ops that
// satisfy the compiler. The Login flow never sets mfa_required=true in
// core build (field is false by default in DB), so these are never called.
package auth

import (
	"fmt"

	"github.com/shadowai/backend/internal/domain"
)

func (s *Service) IssueMFAChallenge(_ string) (string, error) {
	return "", fmt.Errorf("mfa not available in core build")
}

func (s *Service) generateMFAToken(u *domain.User) (string, error) {
	return s.generateToken(u)
}

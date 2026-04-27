package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/shadowai/backend/internal/domain"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrWeakPassword       = errors.New("password too weak")
	ErrInvalidRole        = errors.New("invalid role")
	// ErrMFARequired is returned by Login when the user has mfa_required=true.
	// The caller should redirect to /api/auth/mfa/verify with the MFA challenge token.
	ErrMFARequired = errors.New("mfa required")
)

const (
	RoleAdmin   = "admin"
	RoleUser    = "user"
	RoleAnalyst = "analyst"
	RoleAuditor = "auditor"
	// RoleGlobalAdmin is a special cross-tenant role. It cannot be set via
	// normal registration (NormalizeRole rejects it); it must be assigned via
	// direct DB write or admin API by an existing global_admin.
	RoleGlobalAdmin = "global_admin"
)

var allowedRoles = map[string]struct{}{
	RoleAdmin:   {},
	RoleUser:    {},
	RoleAnalyst: {},
	RoleAuditor: {},
}

// IsGlobalClaims returns true for break-glass sessions and global_admin role.
// Both bypass per-org tenant filters.
func IsGlobalClaims(c *Claims) bool {
	return c != nil && (c.BreakGlass || c.Role == RoleGlobalAdmin)
}

// IsPrivilegedAdminRole возвращает true для ролей с правами
// привилегированного администрирования контура управления. global_admin включён
// намеренно: межарендаторный admin должен проходить те же MFA требования, что и
// admin арендатора.
func IsPrivilegedAdminRole(role string) bool {
	return role == RoleAdmin || role == RoleGlobalAdmin
}

// RequireOrg extracts the org scope from claims.
// Returns (orgID, false, nil) for normal tenant sessions.
// Returns ("", true, nil) for break-glass / global_admin (no org restriction).
// Returns ("", false, err) if claims are nil or org is missing for a non-global session.
func RequireOrg(c *Claims) (orgID string, global bool, err error) {
	if c == nil {
		return "", false, fmt.Errorf("no auth claims")
	}
	if IsGlobalClaims(c) {
		return "", true, nil
	}
	if c.OrgID == "" {
		return "", false, fmt.Errorf("missing org_id in claims")
	}
	return c.OrgID, false, nil
}

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	// OrgID is the organization scope for this session (PR-T2.2).
	// Set from users.org_id by AuthMiddleware after DB lookup — never from JWT payload.
	// Empty string only for break-glass/global sessions (BreakGlass=true).
	// Middleware rejects non-break-glass sessions with empty OrgID (fail-closed).
	OrgID string `json:"org_id,omitempty"`
	// Department is the user's organizational department, populated from users.department.
	// Used by PR-G3 context_scoped governance routing. Empty string = no department assigned.
	// This field is server-issued (trusted). Request headers must NOT override it.
	Department   string `json:"department,omitempty"`
	TokenVersion int    `json:"tv"`
	// PR-E1.1: MFA and break-glass session markers.
	// MFAVerified=true — session was authenticated with TOTP code in addition to password.
	MFAVerified bool `json:"mfa_verified,omitempty"`
	// BreakGlass=true — short-lived emergency session (1h TTL, all actions audited).
	BreakGlass bool `json:"break_glass,omitempty"`
	jwt.RegisteredClaims
}

type Service struct {
	repo             *Repository
	jwtSecret        []byte
	adminMFARequired bool // PR-E1.1: if true, all admin sessions must have MFAVerified=true
}

func NormalizeRole(raw string) (string, error) {
	role := strings.ToLower(strings.TrimSpace(raw))
	if role == "" {
		role = RoleUser
	}
	if _, ok := allowedRoles[role]; !ok {
		return "", ErrInvalidRole
	}
	return role, nil
}

// ServiceOption configures a Service.
type ServiceOption func(*Service)

// WithAdminMFARequired enforces MFA for all admin sessions regardless of
// per-user mfa_required flag. Admin API-key and JWT sessions without
// MFAVerified=true are rejected with 401 when this is set.
func WithAdminMFARequired() ServiceOption {
	return func(s *Service) { s.adminMFARequired = true }
}

func NewService(repo *Repository, jwtSecret string, opts ...ServiceOption) *Service {
	s := &Service{repo: repo, jwtSecret: []byte(jwtSecret)}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Service) Register(ctx context.Context, email, password, role string) (*domain.User, error) {
	normRole, err := NormalizeRole(role)
	if err != nil {
		return nil, err
	}
	existing, _ := s.repo.GetByEmail(ctx, email)
	if existing != nil {
		return nil, ErrUserExists
	}
	if len(password) < 12 {
		return nil, ErrWeakPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	apiKey, err := generateAPIKey()
	if err != nil {
		return nil, err
	}
	apiKeyHash := hashAPIKey(apiKey)
	u := &domain.User{
		ID:           uuid.New().String(),
		Email:        email,
		Password:     string(hash),
		Role:         normRole,
		APIKey:       apiKeyHash,
		IsActive:     true,
		TokenVersion: 0,
	}
	if err := s.repo.CreateUser(ctx, u); err != nil {
		return nil, err
	}
	u.APIKey = apiKey
	return u, nil
}

func (s *Service) GetUserByAPIKey(ctx context.Context, apiKey string) (*domain.User, error) {
	user, err := s.repo.GetByAPIKey(ctx, apiKey)
	if err == nil {
		return user, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	return s.repo.GetByAPIKeyHash(ctx, hashAPIKey(apiKey))
}

// LoginResult carries the outcome of a login attempt.
type LoginResult struct {
	// Token is set when login is complete (no MFA required or MFA not configured).
	Token string
	// MFARequired is true when the user has MFA enabled; Token is empty.
	// The caller must exchange MFAChallengeToken for a TOTP code at /api/auth/mfa/verify.
	MFARequired bool
	// MFAChallengeToken is a short-lived JWT for the MFA step.
	MFAChallengeToken string
}

func (s *Service) Login(ctx context.Context, email, password string) (string, error) {
	result, err := s.LoginWithMFA(ctx, email, password)
	if err != nil {
		return "", err
	}
	if result.MFARequired {
		return "", ErrMFARequired
	}
	return result.Token, nil
}

// LoginWithMFA performs password verification and returns a LoginResult.
// If the user has mfa_required=true, Token is empty and MFARequired=true.
func (s *Service) LoginWithMFA(ctx context.Context, email, password string) (LoginResult, error) {
	u, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	if !u.IsActive {
		return LoginResult{}, ErrInvalidCredentials
	}
	if u.Password == "" {
		// OIDC-provisioned user; no password login allowed.
		return LoginResult{}, ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)); err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	if u.MFARequired {
		challengeToken, err := s.IssueMFAChallenge(u.ID)
		if err != nil {
			return LoginResult{}, err
		}
		return LoginResult{MFARequired: true, MFAChallengeToken: challengeToken}, nil
	}
	token, err := s.generateToken(u)
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Token: token}, nil
}

func (s *Service) RotateAPIKey(ctx context.Context, userID string) (string, error) {
	newAPIKey, err := generateAPIKey()
	if err != nil {
		return "", err
	}
	hashed := hashAPIKey(newAPIKey)
	if err := s.repo.UpdateAPIKeyHash(ctx, userID, hashed); err != nil {
		return "", err
	}
	return newAPIKey, nil
}

func (s *Service) RevokeTokens(ctx context.Context, userID string) error {
	return s.repo.IncrementTokenVersion(ctx, userID)
}

func (s *Service) GenerateTokenForUserID(ctx context.Context, userID string) (string, error) {
	return s.GenerateTokenForUserIDWithMFA(ctx, userID, false)
}

// GenerateTokenForUserIDWithMFA issues a JWT and optionally sets MFAVerified=true.
// Used by OIDC callback when the IdP confirms MFA via amr/acr claims (PR-E3).
func (s *Service) GenerateTokenForUserIDWithMFA(ctx context.Context, userID string, mfaVerified bool) (string, error) {
	u, err := s.repo.GetByID(ctx, userID)
	if err != nil {
		return "", err
	}
	if !mfaVerified {
		return s.generateToken(u)
	}
	return s.generateMFAToken(u) // generateMFAToken sets MFAVerified=true
}

func (s *Service) ValidateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

func (s *Service) GetRepo() *Repository {
	return s.repo
}

func (s *Service) generateToken(u *domain.User) (string, error) {
	dept := ""
	if u.Department != nil {
		dept = *u.Department
	}
	orgID := u.OrgID
	if orgID == "" {
		orgID = domain.DefaultOrgID
	}
	claims := &Claims{
		UserID:       u.ID,
		Email:        u.Email,
		Role:         u.Role,
		OrgID:        orgID,
		Department:   dept,
		TokenVersion: u.TokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func hashAPIKey(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])
}

func generateAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

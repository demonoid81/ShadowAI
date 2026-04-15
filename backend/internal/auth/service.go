package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"database/sql"
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
	ErrWeakPassword      = errors.New("password too weak")
	ErrInvalidRole       = errors.New("invalid role")
)

const (
	RoleAdmin   = "admin"
	RoleUser    = "user"
	RoleAnalyst = "analyst"
	RoleAuditor = "auditor"
)

var allowedRoles = map[string]struct{}{
	RoleAdmin:   {},
	RoleUser:    {},
	RoleAnalyst: {},
	RoleAuditor: {},
}

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	TokenVersion int `json:"tv"`
	jwt.RegisteredClaims
}

type Service struct {
	repo      *Repository
	jwtSecret []byte
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

func NewService(repo *Repository, jwtSecret string) *Service {
	return &Service{repo: repo, jwtSecret: []byte(jwtSecret)}
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
		ID:       uuid.New().String(),
		Email:    email,
		Password: string(hash),
		Role:     normRole,
		APIKey:   apiKeyHash,
		IsActive: true,
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

func (s *Service) Login(ctx context.Context, email, password string) (string, error) {
	u, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	if !u.IsActive {
		return "", ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)); err != nil {
		return "", ErrInvalidCredentials
	}
	return s.generateToken(u)
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
	u, err := s.repo.GetByID(ctx, userID)
	if err != nil {
		return "", err
	}
	return s.generateToken(u)
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
	claims := &Claims{
		UserID:       u.ID,
		Email:        u.Email,
		Role:         u.Role,
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

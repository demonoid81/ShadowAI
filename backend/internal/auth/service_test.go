package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "test-secret-32-chars-long!!!!!!!"

func newTestService() *Service {
	return NewService(nil, testSecret)
}

func TestNormalizeRole(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{name: "admin lowercase", input: "admin", want: "admin"},
		{name: "user lowercase", input: "user", want: "user"},
		{name: "analyst lowercase", input: "analyst", want: "analyst"},
		{name: "auditor lowercase", input: "auditor", want: "auditor"},
		{name: "mixed case Admin", input: "Admin", want: "admin"},
		{name: "upper case USER with spaces", input: " USER ", want: "user"},
		{name: "mixed case Analyst", input: "  Analyst  ", want: "analyst"},
		{name: "empty string defaults to user", input: "", want: "user"},
		{name: "whitespace only defaults to user", input: "   ", want: "user"},
		{name: "invalid role", input: "superadmin", want: "", wantErr: ErrInvalidRole},
		{name: "invalid role manager", input: "manager", want: "", wantErr: ErrInvalidRole},
		{name: "numeric role", input: "123", want: "", wantErr: ErrInvalidRole},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeRole(tt.input)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("NormalizeRole(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("NormalizeRole(%q) unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("NormalizeRole(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateToken_Valid(t *testing.T) {
	svc := newTestService()

	claims := &Claims{
		UserID:       "user-123",
		Email:        "test@example.com",
		Role:         "admin",
		TokenVersion: 3,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	got, err := svc.ValidateToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
	if got.UserID != "user-123" {
		t.Errorf("UserID = %q, want %q", got.UserID, "user-123")
	}
	if got.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", got.Email, "test@example.com")
	}
	if got.Role != "admin" {
		t.Errorf("Role = %q, want %q", got.Role, "admin")
	}
	if got.TokenVersion != 3 {
		t.Errorf("TokenVersion = %d, want %d", got.TokenVersion, 3)
	}
}

func TestValidateToken_Expired(t *testing.T) {
	svc := newTestService()

	claims := &Claims{
		UserID: "user-123",
		Email:  "test@example.com",
		Role:   "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = svc.ValidateToken(tokenStr)
	if err == nil {
		t.Error("ValidateToken should return error for expired token")
	}
}

func TestValidateToken_WrongSigningMethod(t *testing.T) {
	svc := newTestService()

	claims := &Claims{
		UserID: "user-123",
		Email:  "test@example.com",
		Role:   "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Create a token that claims to use RS256 in the header but is actually
	// signed with HS256 using the secret as key. The validator should reject
	// because the alg header says RS256.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["alg"] = "RS256"
	tokenStr, err := token.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = svc.ValidateToken(tokenStr)
	if err == nil {
		t.Error("ValidateToken should return error for wrong signing method")
	}
}

func TestValidateToken_WrongSecret(t *testing.T) {
	claims := &Claims{
		UserID: "user-123",
		Email:  "test@example.com",
		Role:   "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte("different-secret-32-chars!!!!!!!"))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	svc := newTestService()
	_, err = svc.ValidateToken(tokenStr)
	if err == nil {
		t.Error("ValidateToken should return error for token signed with wrong secret")
	}
}

func TestValidateToken_MalformedToken(t *testing.T) {
	svc := newTestService()

	tests := []struct {
		name     string
		tokenStr string
	}{
		{name: "empty string", tokenStr: ""},
		{name: "garbage", tokenStr: "not.a.jwt.token"},
		{name: "partial", tokenStr: "eyJhbGciOiJIUzI1NiJ9"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ValidateToken(tt.tokenStr)
			if err == nil {
				t.Errorf("ValidateToken(%q) should return error", tt.tokenStr)
			}
		})
	}
}

func TestValidateToken_TableDriven(t *testing.T) {
	svc := newTestService()

	makeToken := func(claims *Claims, secret string, alg jwt.SigningMethod) string {
		token := jwt.NewWithClaims(alg, claims)
		s, err := token.SignedString([]byte(secret))
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}
		return s
	}

	validClaims := &Claims{
		UserID:       "uid-1",
		Email:        "user@test.com",
		Role:         "analyst",
		TokenVersion: 5,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	expiredClaims := &Claims{
		UserID: "uid-2",
		Email:  "expired@test.com",
		Role:   "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}

	tests := []struct {
		name      string
		tokenStr  string
		wantErr   bool
		wantUID   string
		wantEmail string
		wantRole  string
		wantTV    int
	}{
		{
			name:      "valid token returns correct claims",
			tokenStr:  makeToken(validClaims, testSecret, jwt.SigningMethodHS256),
			wantErr:   false,
			wantUID:   "uid-1",
			wantEmail: "user@test.com",
			wantRole:  "analyst",
			wantTV:    5,
		},
		{
			name:     "expired token",
			tokenStr: makeToken(expiredClaims, testSecret, jwt.SigningMethodHS256),
			wantErr:  true,
		},
		{
			name:     "wrong secret",
			tokenStr: makeToken(validClaims, "wrong-secret-32-chars-long!!!!!!!", jwt.SigningMethodHS256),
			wantErr:  true,
		},
		{
			name:     "empty token string",
			tokenStr: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := svc.ValidateToken(tt.tokenStr)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.UserID != tt.wantUID {
				t.Errorf("UserID = %q, want %q", got.UserID, tt.wantUID)
			}
			if got.Email != tt.wantEmail {
				t.Errorf("Email = %q, want %q", got.Email, tt.wantEmail)
			}
			if got.Role != tt.wantRole {
				t.Errorf("Role = %q, want %q", got.Role, tt.wantRole)
			}
			if got.TokenVersion != tt.wantTV {
				t.Errorf("TokenVersion = %d, want %d", got.TokenVersion, tt.wantTV)
			}
		})
	}
}

func TestHashAPIKey_Consistency(t *testing.T) {
	// hashAPIKey is unexported, but we can verify its behavior:
	// it should produce a consistent SHA-256 hex output.
	input := "test-api-key-value"
	expected := sha256Hex(input)

	// Call twice to verify consistency.
	result1 := hashAPIKey(input)
	result2 := hashAPIKey(input)

	if result1 != result2 {
		t.Errorf("hashAPIKey is not consistent: %q != %q", result1, result2)
	}
	if result1 != expected {
		t.Errorf("hashAPIKey(%q) = %q, want %q", input, result1, expected)
	}

	// Verify it's a valid 64-char hex string (SHA-256 = 32 bytes = 64 hex chars).
	if len(result1) != 64 {
		t.Errorf("hashAPIKey output length = %d, want 64", len(result1))
	}
}

func TestHashAPIKey_DifferentInputs(t *testing.T) {
	a := hashAPIKey("key-a")
	b := hashAPIKey("key-b")
	if a == b {
		t.Error("hashAPIKey should produce different outputs for different inputs")
	}
}

func TestGenerateAPIKey_Uniqueness(t *testing.T) {
	key1, err := generateAPIKey()
	if err != nil {
		t.Fatalf("generateAPIKey error: %v", err)
	}
	key2, err := generateAPIKey()
	if err != nil {
		t.Fatalf("generateAPIKey error: %v", err)
	}
	if key1 == key2 {
		t.Error("generateAPIKey should produce unique keys")
	}
	// 32 bytes = 64 hex chars
	if len(key1) != 64 {
		t.Errorf("generateAPIKey length = %d, want 64", len(key1))
	}
}

// sha256Hex is a test helper that computes SHA-256 hex independently.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

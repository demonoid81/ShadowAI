//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// PR-E1.1: TOTP-based MFA for admin accounts.
//
// Flow:
//   1. Admin calls POST /api/auth/login → password correct, mfa_required=true
//      Response: {"mfa_required":true, "mfa_token":"<short-lived-token>"}
//   2. Admin calls POST /api/auth/mfa/verify {"mfa_token":"...", "code":"123456"}
//      Response: {"token":"<full-jwt>"} or 401
//
// Setup flow (authenticated admin):
//   1. POST /api/auth/mfa/setup → {"uri":"otpauth://...", "secret":"..."}
//   2. Admin scans QR code in authenticator app
//   3. POST /api/auth/mfa/confirm {"code":"123456"} → 200 OK (MFA enabled)
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"github.com/shadowai/backend/internal/domain"
)

const (
	mfaTokenExpiry   = 5 * time.Minute
	setupTokenExpiry = 10 * time.Minute // longer — user needs time to scan QR
	totpDigits       = 6
)

// MFAToken is a short-lived JWT issued after password verification when MFA is required.
// The user must submit this token + TOTP code to receive a full JWT.
type MFAChallengeToken struct {
	UserID    string `json:"uid"`
	TokenType string `json:"type"` // "mfa_challenge"
	jwt.RegisteredClaims
}

// IssueMFAChallenge creates a short-lived challenge token after successful password check.
func (s *Service) IssueMFAChallenge(userID string) (string, error) {
	claims := &MFAChallengeToken{
		UserID:    userID,
		TokenType: "mfa_challenge",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(mfaTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// VerifyMFAChallenge validates the challenge token and returns the user ID.
func (s *Service) VerifyMFAChallenge(tokenStr string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &MFAChallengeToken{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return "", fmt.Errorf("invalid mfa_token")
	}
	claims, ok := token.Claims.(*MFAChallengeToken)
	if !ok || !token.Valid || claims.TokenType != "mfa_challenge" {
		return "", fmt.Errorf("invalid mfa_token type")
	}
	return claims.UserID, nil
}

// SetupToken is a short-lived JWT carrying an encrypted pending TOTP secret.
// It is returned from /mfa/setup and must be presented to /mfa/confirm.
// The secret is NOT saved to the DB until confirm succeeds, preventing lockout
// if the user fails to scan the QR code.
type SetupToken struct {
	UserID          string `json:"uid"`
	TokenType       string `json:"type"` // "mfa_setup"
	EncryptedSecret string `json:"enc"`  // encryptTOTPSecret output
	jwt.RegisteredClaims
}

// IssueSetupToken creates a setup_token containing the pending encrypted secret.
func (s *Service) IssueSetupToken(userID, encryptedSecret string) (string, error) {
	claims := &SetupToken{
		UserID:          userID,
		TokenType:       "mfa_setup",
		EncryptedSecret: encryptedSecret,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(setupTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// VerifySetupToken validates a setup_token and returns the encrypted secret + userID.
func (s *Service) VerifySetupToken(tokenStr string) (userID, encryptedSecret string, err error) {
	token, err := jwt.ParseWithClaims(tokenStr, &SetupToken{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return "", "", fmt.Errorf("invalid setup_token")
	}
	claims, ok := token.Claims.(*SetupToken)
	if !ok || !token.Valid || claims.TokenType != "mfa_setup" {
		return "", "", fmt.Errorf("invalid setup_token type")
	}
	return claims.UserID, claims.EncryptedSecret, nil
}

// GenerateTOTPSecret creates a new TOTP secret for the user and returns the OTP URI.
// The secret is returned as base32 for the user to enter manually if QR fails.
// The encrypted secret for DB storage is returned as encryptedSecret.
func (s *Service) GenerateTOTPSecret(issuer, accountName string) (uri, plainSecret, encryptedSecret string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      30,
		Digits:      totpDigits,
	})
	if err != nil {
		return "", "", "", fmt.Errorf("totp generate: %w", err)
	}
	plain := key.Secret()
	enc := encryptTOTPSecret(s.jwtSecret, plain)
	return key.URL(), plain, enc, nil
}

// validateTOTPCode checks a code against a plain TOTP secret string.
func validateTOTPCode(plainSecret, code string) bool {
	return totp.Validate(code, plainSecret)
}

// ValidateTOTPCode checks a TOTP code against the user's stored encrypted secret.
func (s *Service) ValidateTOTPCode(ctx context.Context, userID, code string) error {
	u, err := s.repo.GetByID(ctx, userID)
	if err != nil || u.TOTPSecret == nil || *u.TOTPSecret == "" {
		return fmt.Errorf("mfa not configured for user")
	}
	plain, err := decryptTOTPSecret(s.jwtSecret, *u.TOTPSecret)
	if err != nil {
		return fmt.Errorf("mfa: decrypt secret: %w", err)
	}
	if !validateTOTPCode(plain, code) {
		return fmt.Errorf("invalid totp code")
	}
	return nil
}

// generateMFAToken issues a full JWT with MFAVerified=true.
func (s *Service) generateMFAToken(u *domain.User) (string, error) {
	dept := ""
	if u.Department != nil {
		dept = *u.Department
	}
	claims := &Claims{
		UserID:       u.ID,
		Email:        u.Email,
		Role:         u.Role,
		Department:   dept,
		TokenVersion: u.TokenVersion,
		MFAVerified:  true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// ---------------------------------------------------------------------------
// TOTP secret storage.
// The secret is stored base32-encoded (the canonical TOTP format) and XOR-obfuscated
// with a key-derived stream to prevent trivial plaintext leakage in DB dumps.
//
// Production note: for stronger at-rest protection, use pgcrypto column encryption
// or a KMS-backed envelope key rather than this server-side obfuscation.
// ---------------------------------------------------------------------------

// keyStream returns a deterministic pseudo-random stream derived from key.
// Length: 64 bytes (covers up to 64-char TOTP secrets).
func keyStream(key []byte) []byte {
	h1 := hmac.New(sha256.New, key)
	h1.Write([]byte("shadowai:totp:stream:1"))
	h2 := hmac.New(sha256.New, key)
	h2.Write([]byte("shadowai:totp:stream:2"))
	return append(h1.Sum(nil), h2.Sum(nil)...)
}

// encryptTOTPSecret obfuscates a TOTP secret for DB storage.
func encryptTOTPSecret(key []byte, plain string) string {
	stream := keyStream(key)
	b := []byte(plain)
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ stream[i%len(stream)]
	}
	return hex.EncodeToString(out)
}

// decryptTOTPSecret reverses encryptTOTPSecret.
func decryptTOTPSecret(key []byte, enc string) (string, error) {
	raw, err := hex.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	stream := keyStream(key)
	out := make([]byte, len(raw))
	for i, c := range raw {
		out[i] = c ^ stream[i%len(stream)]
	}
	return string(out), nil
}

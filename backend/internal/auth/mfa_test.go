//go:build enterprise

package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// TestMFAChallenge_RoundTrip — issue challenge, verify it, extract user ID.
func TestMFAChallenge_RoundTrip(t *testing.T) {
	svc := &Service{jwtSecret: []byte("test-secret-for-mfa-32chars!!!!")}
	token, err := svc.IssueMFAChallenge("user-123")
	if err != nil {
		t.Fatalf("IssueMFAChallenge: %v", err)
	}
	if token == "" {
		t.Error("challenge token must not be empty")
	}
	userID, err := svc.VerifyMFAChallenge(token)
	if err != nil {
		t.Fatalf("VerifyMFAChallenge: %v", err)
	}
	if userID != "user-123" {
		t.Errorf("userID = %q, want user-123", userID)
	}
}

// TestMFAChallenge_InvalidToken_Rejected.
func TestMFAChallenge_InvalidToken_Rejected(t *testing.T) {
	svc := &Service{jwtSecret: []byte("test-secret-for-mfa-32chars!!!!")}
	_, err := svc.VerifyMFAChallenge("not-a-valid-token")
	if err == nil {
		t.Error("expected error for invalid token, got nil")
	}
}

// TestTOTPSecretEncryption_RoundTrip — encrypt and decrypt secret.
func TestTOTPSecretEncryption_RoundTrip(t *testing.T) {
	key := []byte("test-key-for-totp-encryption!!!!")
	plain := "JBSWY3DPEHPK3PXP" // example TOTP base32 secret

	enc := encryptTOTPSecret(key, plain)
	if enc == plain {
		t.Error("encrypted secret must differ from plain")
	}

	got, err := decryptTOTPSecret(key, enc)
	if err != nil {
		t.Fatalf("decryptTOTPSecret: %v", err)
	}
	if got != plain {
		t.Errorf("decrypted = %q, want %q", got, plain)
	}
}

// TestTOTPSecretEncryption_DifferentKey_Fails.
func TestTOTPSecretEncryption_DifferentKey_Fails(t *testing.T) {
	key1 := []byte("key-one-for-totp-32chars!!!!!!!")
	key2 := []byte("key-two-for-totp-32chars!!!!!!!")
	plain := "JBSWY3DPEHPK3PXP"

	enc := encryptTOTPSecret(key1, plain)
	got, _ := decryptTOTPSecret(key2, enc)
	if got == plain {
		t.Error("decryption with wrong key must not produce the original plaintext")
	}
}

// TestGenerateTOTPSecret — generates a valid OTP URI and verifiable code.
func TestGenerateTOTPSecret(t *testing.T) {
	svc := &Service{jwtSecret: []byte("test-secret-for-totp-generation!")}
	uri, plainSecret, encSecret, err := svc.GenerateTOTPSecret("TestApp", "user@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if !isURL(uri) {
		t.Errorf("uri = %q, want otpauth:// URL", uri)
	}
	if plainSecret == "" || encSecret == "" {
		t.Error("plain and encrypted secrets must be non-empty")
	}

	// Verify that the generated secret produces a valid TOTP code.
	code, err := totp.GenerateCode(plainSecret, time.Now())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	if !totp.Validate(code, plainSecret) {
		t.Error("generated TOTP code is not valid against its own secret")
	}
}

func isURL(s string) bool {
	return len(s) > 10 && s[:10] == "otpauth://"
}

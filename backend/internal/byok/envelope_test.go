package byok

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAESGCMEncryptor_RoundTripEnvelope(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	enc, err := NewAESGCMEncryptor("test-key", key)
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}

	ciphertext, err := enc.EncryptField(context.Background(), "org-a", "request_body", "secret prompt")
	if err != nil {
		t.Fatalf("EncryptField: %v", err)
	}
	if !IsEnvelopeString(ciphertext) {
		t.Fatalf("ciphertext is not BYOK envelope: %q", ciphertext)
	}
	if strings.Contains(ciphertext, "secret prompt") {
		t.Fatalf("ciphertext leaked plaintext: %q", ciphertext)
	}

	plaintext, err := enc.DecryptField(context.Background(), ciphertext)
	if err != nil {
		t.Fatalf("DecryptField: %v", err)
	}
	if plaintext != "secret prompt" {
		t.Fatalf("DecryptField=%q, want plaintext", plaintext)
	}
}

func TestAESGCMEncryptor_TamperFails(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	enc, err := NewAESGCMEncryptor("test-key", key)
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}

	ciphertext, err := enc.EncryptField(context.Background(), "org-a", "response_body", "secret response")
	if err != nil {
		t.Fatalf("EncryptField: %v", err)
	}
	env, err := DecodeEnvelope(ciphertext)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	env.CT = env.CT[:len(env.CT)-2] + "xx"
	tampered, err := EncodeEnvelope(env)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}

	if _, err := enc.DecryptField(context.Background(), tampered); err == nil {
		t.Fatal("DecryptField(tampered) expected error")
	}
}

func TestDecodeEnvelopeRejectsPlaintext(t *testing.T) {
	if IsEnvelopeString("plain body") {
		t.Fatal("plain body must not be detected as BYOK envelope")
	}
	if _, err := DecodeEnvelope("plain body"); err == nil {
		t.Fatal("DecodeEnvelope(plaintext) expected error")
	}
}

func TestVaultTransitEncryptor_EncryptDecrypt(t *testing.T) {
	var sawEncrypt, sawDecrypt bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "vault-token" {
			t.Fatalf("missing vault token header")
		}
		switch r.URL.Path {
		case "/v1/transit/encrypt/audit-key":
			sawEncrypt = true
			var req struct {
				Plaintext string `json:"plaintext"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode encrypt request: %v", err)
			}
			raw, err := base64.StdEncoding.DecodeString(req.Plaintext)
			if err != nil {
				t.Fatalf("plaintext is not base64: %v", err)
			}
			if string(raw) != "secret prompt" {
				t.Fatalf("plaintext=%q", raw)
			}
			_, _ = w.Write([]byte(`{"data":{"ciphertext":"vault:v1:wrapped"}}`))
		case "/v1/transit/decrypt/audit-key":
			sawDecrypt = true
			var req struct {
				Ciphertext string `json:"ciphertext"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode decrypt request: %v", err)
			}
			if req.Ciphertext != "vault:v1:wrapped" {
				t.Fatalf("ciphertext=%q", req.Ciphertext)
			}
			pt := base64.StdEncoding.EncodeToString([]byte("secret prompt"))
			_, _ = w.Write([]byte(`{"data":{"plaintext":"` + pt + `"}}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	enc, err := NewVaultTransitEncryptor(VaultTransitConfig{
		Addr:    srv.URL,
		Token:   "vault-token",
		Mount:   "transit",
		KeyName: "audit-key",
	})
	if err != nil {
		t.Fatalf("NewVaultTransitEncryptor: %v", err)
	}
	ciphertext, err := enc.EncryptField(context.Background(), "org-a", "request_body", "secret prompt")
	if err != nil {
		t.Fatalf("EncryptField: %v", err)
	}
	env, err := DecodeEnvelope(ciphertext)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	if env.Alg != AlgVaultTransit || env.KID != "vault:transit/audit-key" || env.Field != "request_body" {
		t.Fatalf("unexpected envelope: %+v", env)
	}

	plaintext, err := enc.DecryptField(context.Background(), ciphertext)
	if err != nil {
		t.Fatalf("DecryptField: %v", err)
	}
	if plaintext != "secret prompt" {
		t.Fatalf("plaintext=%q", plaintext)
	}
	if !sawEncrypt || !sawDecrypt {
		t.Fatalf("expected both encrypt and decrypt calls, saw encrypt=%v decrypt=%v", sawEncrypt, sawDecrypt)
	}
}

func TestVaultTransitEncryptor_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "vault unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	enc, err := NewVaultTransitEncryptor(VaultTransitConfig{
		Addr:    srv.URL,
		Token:   "vault-token",
		Mount:   "transit",
		KeyName: "audit-key",
	})
	if err != nil {
		t.Fatalf("NewVaultTransitEncryptor: %v", err)
	}
	if _, err := enc.EncryptField(context.Background(), "org-a", "request_body", "secret prompt"); err == nil {
		t.Fatal("EncryptField expected vault status error")
	}
}

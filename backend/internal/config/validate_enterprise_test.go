//go:build enterprise

// PR-L1.3: Enterprise-only config validation tests. В Core build
// эти проверки отключены (validate_core.go stub), поэтому и тесты
// tag'нуты enterprise — core test suite их не запускает.

package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// TestValidateStartupConfig_LegalHoldSecretMissing — PR-L1.2 guard.
// Prod + enterprise build без LEGAL_HOLD_TOKEN_SECRET отвергается
// (plain hash brute-force-weak для guessable case IDs).
func TestValidateStartupConfig_LegalHoldSecretMissing(t *testing.T) {
	cfg := prodConfigBase()
	cfg.LegalHoldTokenSecret = ""
	err := cfg.ValidateStartupConfig()
	if err == nil || !strings.Contains(err.Error(), "LEGAL_HOLD_TOKEN_SECRET") {
		t.Fatalf("expected LEGAL_HOLD_TOKEN_SECRET error, got %v", err)
	}
}

// TestValidateStartupConfig_LegalHoldSecretTooShort — короткий secret
// отвергается (insufficient entropy для HMAC).
func TestValidateStartupConfig_LegalHoldSecretTooShort(t *testing.T) {
	cfg := prodConfigBase()
	cfg.LegalHoldTokenSecret = "short" // <32 chars
	err := cfg.ValidateStartupConfig()
	if err == nil || !strings.Contains(err.Error(), ">=32 chars") {
		t.Fatalf("expected length error, got %v", err)
	}
}

// TestValidateStartupConfig_LegalHoldSecretOK — >=32 chars проходит
// в enterprise build.
func TestValidateStartupConfig_LegalHoldSecretOK(t *testing.T) {
	cfg := prodConfigBase()
	// prodConfigBase уже задаёт 32+ char secret.
	if err := cfg.ValidateStartupConfig(); err != nil {
		t.Fatalf("ok secret: unexpected error: %v", err)
	}
}

// TestValidateStartupConfig_LegalHoldSecret_DevIgnored — dev env
// принимает пустой secret (fallback на unkeyed + warning).
func TestValidateStartupConfig_LegalHoldSecret_DevIgnored(t *testing.T) {
	cfg := &Config{
		AppEnv:               "development",
		LegalHoldTokenSecret: "", // OK в dev
	}
	if err := cfg.ValidateStartupConfig(); err != nil {
		t.Fatalf("dev env: unexpected error: %v", err)
	}
}

// TestValidateStartupConfig_W4_AnchorKeyMismatch — PR-W4.1 review fix:
// AUDIT_ANCHOR_PUBKEY несовпадающий с AUDIT_ANCHOR_SIGNING_KEY → error на startup.
func TestValidateStartupConfig_W4_AnchorKeyMismatch(t *testing.T) {
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	_ = priv1

	signingKeyB64 := base64.StdEncoding.EncodeToString([]byte(priv2))
	pubKeyB64 := base64.StdEncoding.EncodeToString([]byte(pub1))

	cfg := prodConfigBase()
	cfg.AuditAnchorSigningKey = signingKeyB64
	cfg.AuditAnchorPubKeyID = "ed25519-k1"
	cfg.AuditAnchorPubKey = pubKeyB64
	err := cfg.ValidateStartupConfig()
	if err == nil {
		t.Fatal("expected error for mismatched key pair")
	}
	if !strings.Contains(err.Error(), "AUDIT_ANCHOR_PUBKEY") {
		t.Errorf("error should mention AUDIT_ANCHOR_PUBKEY: %v", err)
	}
}

// TestValidateStartupConfig_W4_AnchorKeyMatch — совпадающая пара → OK.
func TestValidateStartupConfig_W4_AnchorKeyMatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := prodConfigBase()
	cfg.AuditAnchorSigningKey = base64.StdEncoding.EncodeToString([]byte(priv))
	cfg.AuditAnchorPubKeyID = "ed25519-k1"
	cfg.AuditAnchorPubKey = base64.StdEncoding.EncodeToString([]byte(pub))
	if err := cfg.ValidateStartupConfig(); err != nil {
		t.Fatalf("matching key pair should not error: %v", err)
	}
}

// TestValidateStartupConfig_ImmuDBRestProfile_Invalid — PR-W4.3.1: опечатка
// в AUDIT_IMMUDB_REST_PROFILE должна быть отвергнута (не молчаливый fallback).
func TestValidateStartupConfig_ImmuDBRestProfile_Invalid(t *testing.T) {
	for _, bad := range []string{"immudb_v22", "IMMUDB_V2", "v2", "immugw"} {
		cfg := prodConfigBase()
		cfg.AuditImmuDBRestProfile = bad
		err := cfg.ValidateStartupConfig()
		if err == nil {
			t.Errorf("profile %q: expected error, got nil", bad)
			continue
		}
		if !strings.Contains(err.Error(), "AUDIT_IMMUDB_REST_PROFILE") {
			t.Errorf("profile %q: error should mention AUDIT_IMMUDB_REST_PROFILE: %v", bad, err)
		}
	}
}

// TestValidateStartupConfig_ImmuDBRestProfile_Valid — known profile values pass.
func TestValidateStartupConfig_ImmuDBRestProfile_Valid(t *testing.T) {
	for _, ok := range []string{"", "immugw_v1", "immudb_v2"} {
		cfg := prodConfigBase()
		cfg.AuditImmuDBRestProfile = ok
		err := cfg.ValidateStartupConfig()
		// Profile validation should not cause an error.
		if err != nil && strings.Contains(err.Error(), "AUDIT_IMMUDB_REST_PROFILE") {
			t.Errorf("profile %q: unexpected profile error: %v", ok, err)
		}
	}
}

// ---------------------------------------------------------------------------
// PR-F8: semantic_v2 prod validation tests
// ---------------------------------------------------------------------------

// TestValidateStartupConfig_SAV2_MissingEmbeddingEndpoint — SA_v2 enabled
// without embedding endpoint must be rejected in prod (every inspect fail-opens).
func TestValidateStartupConfig_SAV2_MissingEmbeddingEndpoint(t *testing.T) {
	cfg := prodConfigBase()
	cfg.FirewallSAV2Enabled = true
	cfg.FirewallSAV2CorpusPath = "corpus.json"
	cfg.FirewallEmbeddingProvider = "ollama"
	cfg.FirewallEmbeddingEndpoint = "" // missing
	err := cfg.ValidateStartupConfig()
	if err == nil {
		t.Fatal("expected error for SA_v2 without embedding endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "FIREWALL_EMBEDDING_ENDPOINT") {
		t.Errorf("error should mention FIREWALL_EMBEDDING_ENDPOINT: %v", err)
	}
}

// TestValidateStartupConfig_SAV2_MissingProvider — SA_v2 enabled without
// embedding provider must be rejected.
func TestValidateStartupConfig_SAV2_MissingProvider(t *testing.T) {
	cfg := prodConfigBase()
	cfg.FirewallSAV2Enabled = true
	cfg.FirewallSAV2CorpusPath = "corpus.json"
	cfg.FirewallEmbeddingProvider = "" // missing
	cfg.FirewallEmbeddingEndpoint = "http://ollama.internal:11434"
	err := cfg.ValidateStartupConfig()
	if err == nil {
		t.Fatal("expected error for SA_v2 without provider, got nil")
	}
	if !strings.Contains(err.Error(), "FIREWALL_EMBEDDING_PROVIDER") {
		t.Errorf("error should mention FIREWALL_EMBEDDING_PROVIDER: %v", err)
	}
}

// TestValidateStartupConfig_SAV2_MissingCorpusPath — SA_v2 enabled without
// corpus path must be rejected in prod.
func TestValidateStartupConfig_SAV2_MissingCorpusPath(t *testing.T) {
	cfg := prodConfigBase()
	cfg.FirewallSAV2Enabled = true
	cfg.FirewallSAV2CorpusPath = "" // missing
	cfg.FirewallEmbeddingProvider = "ollama"
	cfg.FirewallEmbeddingEndpoint = "http://ollama.internal:11434"
	err := cfg.ValidateStartupConfig()
	if err == nil {
		t.Fatal("expected error for SA_v2 without corpus path, got nil")
	}
	if !strings.Contains(err.Error(), "FIREWALL_SA_V2_CORPUS_PATH") {
		t.Errorf("error should mention FIREWALL_SA_V2_CORPUS_PATH: %v", err)
	}
}

// TestValidateStartupConfig_SAV2_Disabled_NoValidation — SA_v2 disabled
// does not trigger embedding config validation.
func TestValidateStartupConfig_SAV2_Disabled_NoValidation(t *testing.T) {
	cfg := prodConfigBase()
	cfg.FirewallSAV2Enabled = false
	cfg.FirewallEmbeddingEndpoint = "" // would fail if SA_v2 was enabled
	if err := cfg.ValidateStartupConfig(); err != nil {
		if strings.Contains(err.Error(), "FIREWALL_EMBEDDING") || strings.Contains(err.Error(), "SA_V2") {
			t.Errorf("SA_v2 disabled: unexpected SA_v2 validation error: %v", err)
		}
	}
}

// TestValidateStartupConfig_ImmuDBV2PlusAPIPrefix_Rejected — PR-W4.3.1:
// immudb_v2 + AUDIT_IMMUDB_API_PREFIX вместе — это конфликт (v2 игнорирует APIPrefix).
func TestValidateStartupConfig_ImmuDBV2PlusAPIPrefix_Rejected(t *testing.T) {
	cfg := prodConfigBase()
	cfg.AuditImmuDBRestProfile = "immudb_v2"
	cfg.AuditImmuDBAPIPrefix = "/api/v2"
	err := cfg.ValidateStartupConfig()
	if err == nil {
		t.Fatal("expected error for v2 profile + APIPrefix conflict, got nil")
	}
	if !strings.Contains(err.Error(), "AUDIT_IMMUDB_API_PREFIX") {
		t.Errorf("error should mention AUDIT_IMMUDB_API_PREFIX: %v", err)
	}
}

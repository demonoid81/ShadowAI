//go:build enterprise

// PR-L1.3: Enterprise-only config validation tests. В Core build
// эти проверки отключены (validate_core.go stub), поэтому и тесты
// tag'нуты enterprise — core test suite их не запускает.

package config

import (
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

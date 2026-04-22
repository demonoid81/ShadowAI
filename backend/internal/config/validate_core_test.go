//go:build !enterprise

// PR-L1.3 regression guard: в Core-build (pure Apache) startup
// не должен требовать enterprise env vars — это контракт L-1.

package config

import "testing"

// TestValidateStartupConfig_Core_NoLegalHoldSecretRequired —
// критично. Prod core-build deploy НЕ обязан задавать
// LEGAL_HOLD_TOKEN_SECRET, так как legalhold код вообще не
// скомпилирован в binary. Без этого guard'а Core operator'ы
// получали бы 500 при startup на «ровном месте» (PR-L1.2 regression).
func TestValidateStartupConfig_Core_NoLegalHoldSecretRequired(t *testing.T) {
	cfg := &Config{
		AppEnv:             "production",
		DatabaseURL:        "postgres://u:p@db.internal:5432/db?sslmode=require",
		RedisURL:           "redis://redis.internal:6379/0",
		JWTSecret:          "super-secret-key-for-production-12345",
		AuditPayloadMode:   "redacted",
		AuditRetentionDays: 30,
		// LegalHoldTokenSecret намеренно пустой. Core build это
		// допустим — enterprise validation hook — no-op.
		LegalHoldTokenSecret: "",
	}
	if err := cfg.ValidateStartupConfig(); err != nil {
		t.Fatalf("core prod config without LEGAL_HOLD_TOKEN_SECRET: unexpected error: %v", err)
	}
}

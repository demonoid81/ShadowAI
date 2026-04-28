package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoad_BYOKEnv(t *testing.T) {
	t.Setenv("BYOK_ENABLED", "true")
	t.Setenv("BYOK_PROVIDER", "vault_transit")
	t.Setenv("BYOK_VAULT_ADDR", "https://vault.example.com")
	t.Setenv("BYOK_VAULT_TOKEN", "token")
	t.Setenv("BYOK_VAULT_MOUNT", "tenant-transit")
	t.Setenv("BYOK_VAULT_KEY_NAME", "audit-payload")
	t.Setenv("BYOK_TIMEOUT", "7s")

	cfg := Load()
	if !cfg.BYOKEnabled {
		t.Fatal("BYOKEnabled=false")
	}
	if cfg.BYOKProvider != "vault_transit" ||
		cfg.BYOKVaultAddr != "https://vault.example.com" ||
		cfg.BYOKVaultToken != "token" ||
		cfg.BYOKVaultMount != "tenant-transit" ||
		cfg.BYOKVaultKeyName != "audit-payload" ||
		cfg.BYOKTimeout != 7*time.Second {
		t.Fatalf("unexpected BYOK config: %+v", cfg)
	}
}

func TestValidateStartupConfig_BYOKProdRequiresVaultTransit(t *testing.T) {
	cfg := prodConfigBase()
	cfg.BYOKEnabled = true
	cfg.BYOKProvider = "static_aes_gcm"
	cfg.BYOKStaticKeyB64 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="

	err := cfg.ValidateStartupConfig()
	if err == nil || !strings.Contains(err.Error(), "BYOK_PROVIDER") {
		t.Fatalf("expected BYOK_PROVIDER prod error, got %v", err)
	}
}

func TestValidateStartupConfig_BYOKProdRequiresVaultFields(t *testing.T) {
	cfg := prodConfigBase()
	cfg.BYOKEnabled = true
	cfg.BYOKProvider = "vault_transit"

	err := cfg.ValidateStartupConfig()
	if err == nil {
		t.Fatal("expected missing vault config error")
	}
	msg := err.Error()
	for _, want := range []string{"BYOK_VAULT_ADDR", "BYOK_VAULT_TOKEN", "BYOK_VAULT_KEY_NAME"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q does not contain %q", msg, want)
		}
	}
}

func TestValidateStartupConfig_BYOKProdRejectsLoopbackVault(t *testing.T) {
	cfg := prodConfigBase()
	cfg.BYOKEnabled = true
	cfg.BYOKProvider = "vault_transit"
	cfg.BYOKVaultAddr = "http://127.0.0.1:8200"
	cfg.BYOKVaultToken = "token"
	cfg.BYOKVaultKeyName = "audit-payload"

	err := cfg.ValidateStartupConfig()
	if err == nil || !strings.Contains(err.Error(), "BYOK_VAULT_ADDR must not point to localhost") {
		t.Fatalf("expected loopback vault error, got %v", err)
	}
}

func TestValidateStartupConfig_BYOKProdVaultTransitOK(t *testing.T) {
	cfg := prodConfigBase()
	cfg.BYOKEnabled = true
	cfg.BYOKProvider = "vault_transit"
	cfg.BYOKVaultAddr = "https://vault.internal:8200"
	cfg.BYOKVaultToken = "token"
	cfg.BYOKVaultKeyName = "audit-payload"

	if err := cfg.ValidateStartupConfig(); err != nil {
		t.Fatalf("ValidateStartupConfig: %v", err)
	}
}

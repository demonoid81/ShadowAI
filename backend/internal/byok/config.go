package byok

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

type RuntimeConfig struct {
	Provider     string
	VaultAddr    string
	VaultToken   string
	VaultMount   string
	VaultKeyName string
	Timeout      time.Duration
	StaticKeyB64 string
}

func NewEncryptorFromConfig(cfg RuntimeConfig) (Encryptor, error) {
	switch strings.TrimSpace(cfg.Provider) {
	case "vault_transit":
		return NewVaultTransitEncryptor(VaultTransitConfig{
			Addr:    cfg.VaultAddr,
			Token:   cfg.VaultToken,
			Mount:   cfg.VaultMount,
			KeyName: cfg.VaultKeyName,
			Timeout: cfg.Timeout,
		})
	case "static_aes_gcm":
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.StaticKeyB64))
		if err != nil {
			return nil, fmt.Errorf("BYOK_STATIC_KEY_B64 decode: %w", err)
		}
		return NewAESGCMEncryptor("static_aes_gcm", raw)
	default:
		return nil, fmt.Errorf("unsupported BYOK_PROVIDER=%q", cfg.Provider)
	}
}

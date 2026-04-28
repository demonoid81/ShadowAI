package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/byok"
	"github.com/shadowai/backend/internal/config"
)

func configureAuditBYOK(repo *audit.Repository, cfg *config.Config) (*audit.Repository, error) {
	if cfg == nil || !cfg.BYOKEnabled {
		return repo, nil
	}
	enc, err := buildAuditPayloadEncryptor(cfg)
	if err != nil {
		return nil, err
	}
	return repo.WithPayloadEncryptor(enc), nil
}

func buildAuditPayloadEncryptor(cfg *config.Config) (byok.Encryptor, error) {
	switch strings.TrimSpace(cfg.BYOKProvider) {
	case "vault_transit":
		return byok.NewVaultTransitEncryptor(byok.VaultTransitConfig{
			Addr:    cfg.BYOKVaultAddr,
			Token:   cfg.BYOKVaultToken,
			Mount:   cfg.BYOKVaultMount,
			KeyName: cfg.BYOKVaultKeyName,
			Timeout: cfg.BYOKTimeout,
		})
	case "static_aes_gcm":
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.BYOKStaticKeyB64))
		if err != nil {
			return nil, fmt.Errorf("BYOK_STATIC_KEY_B64 decode: %w", err)
		}
		return byok.NewAESGCMEncryptor("static_aes_gcm", raw)
	default:
		return nil, fmt.Errorf("unsupported BYOK_PROVIDER=%q", cfg.BYOKProvider)
	}
}

package main

import (
	"database/sql"

	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/byok"
	"github.com/shadowai/backend/internal/config"
)

func configureAuditBYOK(repo *audit.Repository, cfg *config.Config, db *sql.DB) (*audit.Repository, error) {
	if cfg == nil || !cfg.BYOKEnabled {
		return repo, nil
	}
	enc, err := buildAuditPayloadEncryptor(cfg)
	if err != nil {
		return nil, err
	}
	if db != nil {
		enc = byok.NewEpochEncryptor(enc, byok.NewEpochRepository(db), byok.EpochOptions{
			RequireActive: cfg.BYOKEpochsRequired,
		})
	}
	return repo.WithPayloadEncryptor(enc), nil
}

func buildAuditPayloadEncryptor(cfg *config.Config) (byok.Encryptor, error) {
	return byok.NewEncryptorFromConfig(byok.RuntimeConfig{
		Provider:     cfg.BYOKProvider,
		VaultAddr:    cfg.BYOKVaultAddr,
		VaultToken:   cfg.BYOKVaultToken,
		VaultMount:   cfg.BYOKVaultMount,
		VaultKeyName: cfg.BYOKVaultKeyName,
		Timeout:      cfg.BYOKTimeout,
		StaticKeyB64: cfg.BYOKStaticKeyB64,
	})
}

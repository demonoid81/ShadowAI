//go:build enterprise

// Enterprise-only config validation (PR-L1.3 scope-fix).
// Compiled only under -tags enterprise.
//
// Core-only build (pure Apache) использует validate_core.go с no-op
// stub — это поддерживает L-1 build contract: Core deploy не
// требует enterprise env vars вроде LEGAL_HOLD_TOKEN_SECRET.

package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// parseEd25519PrivKey и parseEd25519PubKey — thin helpers для startup
// validation. Дублируют chain.ParsePrivateKey/ParsePublicKey логику,
// чтобы config пакет не импортировал chain пакет (избегаем cycle).
func parseEd25519PrivKey(b64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decode: %w", err)
		}
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	default:
		return nil, fmt.Errorf("expected %d or %d bytes, got %d", ed25519.PrivateKeySize, ed25519.SeedSize, len(raw))
	}
}

func parseEd25519PubKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decode: %w", err)
		}
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// appendEnterpriseValidations — enterprise-build check'ы, которые
// не применимы к core. Вызывается из общего ValidateStartupConfig
// только когда c.IsProduction() == true (внешняя проверка).
func appendEnterpriseValidations(c *Config, errs []string) []string {
	// PR-L1.2/PR-L1.3: LEGAL_HOLD_TOKEN_SECRET обязателен в prod
	// при enterprise build (legalhold package скомпилирован,
	// case_ref tokenizer реально используется). Для core build
	// эта проверка отключена через //go:build !enterprise stub.
	if strings.TrimSpace(c.LegalHoldTokenSecret) == "" {
		errs = append(errs, "LEGAL_HOLD_TOKEN_SECRET must be set (>=32 chars) in prod to enable keyed HMAC for legal-hold case refs")
	} else if len(c.LegalHoldTokenSecret) < 32 {
		errs = append(errs, "LEGAL_HOLD_TOKEN_SECRET must be >=32 chars (current shorter — insufficient entropy for HMAC)")
	}
	// PR-W4.1: если оба ключа заданы, проверяем что AUDIT_ANCHOR_PUBKEY
	// совпадает с публичным ключом, derived из AUDIT_ANCHOR_SIGNING_KEY.
	// Это ловит misconfiguration (wrong pubkey value) на startup, а не
	// при первом anchor write.
	if strings.TrimSpace(c.AuditAnchorSigningKey) != "" && strings.TrimSpace(c.AuditAnchorPubKey) != "" {
		privKey, privErr := parseEd25519PrivKey(c.AuditAnchorSigningKey)
		pubKey, pubErr := parseEd25519PubKey(c.AuditAnchorPubKey)
		if privErr != nil {
			errs = append(errs, fmt.Sprintf("AUDIT_ANCHOR_SIGNING_KEY invalid: %v", privErr))
		} else if pubErr != nil {
			errs = append(errs, fmt.Sprintf("AUDIT_ANCHOR_PUBKEY invalid: %v", pubErr))
		} else {
			derivedPub := privKey.Public().(ed25519.PublicKey)
			if !bytes.Equal([]byte(derivedPub), []byte(pubKey)) {
				errs = append(errs, "AUDIT_ANCHOR_PUBKEY does not match AUDIT_ANCHOR_SIGNING_KEY derived public key")
			}
		}
	}

	// PR-W4.2: immudb:// sink требует всех четырёх connection fields в prod.
	// Также при immudb:// в prod требуются signing key + pubkey_id.
	if c.AuditAnchorSink == "immudb://" {
		if strings.TrimSpace(c.AuditImmuDBAddr) == "" {
			errs = append(errs, "AUDIT_IMMUDB_ADDR required when AUDIT_ANCHOR_SINK=immudb://")
		}
		if strings.TrimSpace(c.AuditImmuDBUsername) == "" {
			errs = append(errs, "AUDIT_IMMUDB_USERNAME required when AUDIT_ANCHOR_SINK=immudb://")
		}
		if strings.TrimSpace(c.AuditImmuDBPassword) == "" {
			errs = append(errs, "AUDIT_IMMUDB_PASSWORD required when AUDIT_ANCHOR_SINK=immudb://")
		}
		if strings.TrimSpace(c.AuditImmuDBDatabase) == "" {
			errs = append(errs, "AUDIT_IMMUDB_DATABASE required when AUDIT_ANCHOR_SINK=immudb://")
		}
		// immudb:// is an immutable external ledger — signing is mandatory.
		if strings.TrimSpace(c.AuditAnchorSigningKey) == "" {
			errs = append(errs, "AUDIT_ANCHOR_SIGNING_KEY required when AUDIT_ANCHOR_SINK=immudb:// (immutable sink must have signed manifests)")
		}
		if strings.TrimSpace(c.AuditAnchorPubKeyID) == "" {
			errs = append(errs, "AUDIT_ANCHOR_PUBKEY_ID required when AUDIT_ANCHOR_SINK=immudb://")
		}
	}

	// PR-W3: AUDIT_ANCHOR_INTERVAL не должен превышать 24h в prod.
	// Слишком большой интервал = слишком большой window без external witness
	// (rows могут быть удалены и появиться в следующем anchor только через сутки).
	if c.AuditAnchorInterval > 24*time.Hour {
		errs = append(errs, fmt.Sprintf(
			"AUDIT_ANCHOR_INTERVAL=%s exceeds maximum 24h in prod (current compliance gap too large)",
			c.AuditAnchorInterval))
	}
	if c.AuditAnchorSink == "file://" && strings.TrimSpace(c.AuditAnchorSinkPath) == "" {
		errs = append(errs, "AUDIT_ANCHOR_SINK=file:// requires AUDIT_ANCHOR_SINK_PATH in prod")
	}

	// PR-W2: AUDIT_CHAIN_SECRET — keyed HMAC для tamper-evident audit chain.
	// Enterprise prod требует secret для chain writes. Без него chain fields
	// остаются NULL (chain disabled), что допустимо в dev/shadow-mode, но
	// не в prod (reduced tamper-evidence guarantee).
	if strings.TrimSpace(c.AuditChainSecret) == "" {
		errs = append(errs, "AUDIT_CHAIN_SECRET must be set (>=32 chars) in prod for tamper-evident audit chain (RFC PR-W2)")
	} else if len(c.AuditChainSecret) < 32 {
		errs = append(errs, "AUDIT_CHAIN_SECRET must be >=32 chars (insufficient entropy for HMAC chain key)")
	}
	return errs
}

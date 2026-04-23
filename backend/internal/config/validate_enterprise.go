//go:build enterprise

// Enterprise-only config validation (PR-L1.3 scope-fix).
// Compiled only under -tags enterprise.
//
// Core-only build (pure Apache) использует validate_core.go с no-op
// stub — это поддерживает L-1 build contract: Core deploy не
// требует enterprise env vars вроде LEGAL_HOLD_TOKEN_SECRET.

package config

import (
	"fmt"
	"strings"
	"time"
)

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

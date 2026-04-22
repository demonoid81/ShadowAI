//go:build enterprise

// Enterprise-only config validation (PR-L1.3 scope-fix).
// Compiled only under -tags enterprise.
//
// Core-only build (pure Apache) использует validate_core.go с no-op
// stub — это поддерживает L-1 build contract: Core deploy не
// требует enterprise env vars вроде LEGAL_HOLD_TOKEN_SECRET.

package config

import "strings"

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
	return errs
}

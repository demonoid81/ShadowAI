//go:build !enterprise

// Core-only (Apache 2.0) stub для enterprise validation hook.
// Pure core deploy не требует LEGAL_HOLD_TOKEN_SECRET и прочих
// enterprise env vars — они не соответствуют code path'ам,
// скомпилированным в binary.
//
// Enterprise реализация живёт в validate_enterprise.go под
// //go:build enterprise.

package config

func appendEnterpriseValidations(_ *Config, errs []string) []string {
	return errs
}

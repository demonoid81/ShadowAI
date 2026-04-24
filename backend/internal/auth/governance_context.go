package auth

import "net/http"

// GovernanceContext holds the per-request context dimensions used by
// PR-G3 context_scoped governance routing.
type GovernanceContext struct {
	// Department is the user's organizational unit, sourced from the JWT
	// claim (server-issued, trusted). Empty string means no department is
	// assigned — context_scoped policies will deny with CodeUnknownDepartment.
	//
	// Security: department is NOT read from request headers. Headers are
	// client-controlled and could be used to bypass stricter routing
	// (e.g. claiming "finance" to access a model allowed for finance but
	// denied for the caller's real department). Only the JWT claim is trusted.
	Department string

	// Sensitivity is the caller's declared data sensitivity level for this
	// request, sourced from the X-Data-Sensitivity header.
	//
	// Allowed values: "standard", "confidential", "restricted".
	// Missing or unrecognised values → "unknown". In context_scoped mode,
	// "unknown" sensitivity will cause sensitivity_denied unless a rule
	// explicitly allows it — intentionally fail-restrictive.
	Sensitivity string
}

// SensitivityUnknown is used when the X-Data-Sensitivity header is absent or
// contains an unrecognised value. In context_scoped mode this defaults to deny
// unless a rule explicitly covers "unknown" sensitivity.
const SensitivityUnknown = "unknown"

// validSensitivities is the allowlist for X-Data-Sensitivity header values.
var validSensitivities = map[string]bool{
	"standard":     true,
	"confidential": true,
	"restricted":   true,
}

// ExtractGovernanceContext builds a GovernanceContext for the request.
//
// Department: taken from claims.Department only (trusted, server-issued JWT).
// Headers are intentionally not consulted — they can be spoofed by the client
// to obtain more permissive routing.
//
// Sensitivity: taken from the X-Data-Sensitivity request header. If the header
// is absent or contains an unrecognised value, Sensitivity is set to "unknown"
// (fail-restrictive default).
func ExtractGovernanceContext(r *http.Request, claims *Claims) GovernanceContext {
	dept := ""
	if claims != nil {
		dept = claims.Department
	}

	sensitivity := r.Header.Get("X-Data-Sensitivity")
	if !validSensitivities[sensitivity] {
		sensitivity = SensitivityUnknown
	}

	return GovernanceContext{
		Department:  dept,
		Sensitivity: sensitivity,
	}
}

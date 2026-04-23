package chain

import (
	"fmt"
	"sort"
	"strings"
)

// Canonical representations для каждой таблицы.
// Format: "v1|field1|field2|..." — versioned fixed-field concatenation.
// Rules:
//   - Version prefix "v1" позволяет менять layout без breaking existing rows.
//   - NULL → empty string (post-erasure user_id, etc.).
//   - Timestamp → Unix epoch seconds UTC (integer, no timezone variability).
//   - cost_usd → integer microcents (1 USD = 1_000_000 microcents).
//     Избегает float formatting variability между platforms.
//   - pii_types → sorted alphabetically, comma-joined (no spaces).
//   - booleans → "1"/"0".
//   - Separator "|" — не escape'ируется в полях; поля не должны содержать "|"
//     (UUID/int/controlled-vocabulary strings — безопасно).
//
// ВАЖНО: layout не должен меняться для существующих rows с "v1" prefix.
// При необходимости изменить — ввести "v2" layout.

// CanonicalAuditLog возвращает v1 canonical представление для audit_logs row.
// Все параметры — финальные значения, которые будут INSERT'нуты в row.
func CanonicalAuditLog(
	id, userID, model, provider, endpoint string,
	statusCode, promptTokens, completionTokens, totalTokens int,
	costMicrocents int64,
	piiDetected bool,
	piiTypes []string,
	policyAction, outcome, fallbackReason, usageSource string,
	createdAtUnix int64,
) string {
	piiDet := "0"
	if piiDetected {
		piiDet = "1"
	}
	sortedPII := sortedJoin(piiTypes)
	return fmt.Sprintf("v1|%s|%s|%s|%s|%s|%d|%d|%d|%d|%d|%s|%s|%s|%s|%s|%s|%d",
		id, userID, model, provider, endpoint,
		statusCode, promptTokens, completionTokens, totalTokens,
		costMicrocents,
		piiDet, sortedPII,
		policyAction, outcome, fallbackReason, usageSource,
		createdAtUnix,
	)
}

// CanonicalAdminEventLog возвращает v1 canonical для admin_event_logs row.
func CanonicalAdminEventLog(
	id, actorUserID, action, resource, targetID, path, method string,
	statusCode int,
	success bool,
	createdAtUnix int64,
) string {
	succ := "0"
	if success {
		succ = "1"
	}
	return fmt.Sprintf("v1|%s|%s|%s|%s|%s|%s|%s|%d|%s|%d",
		id, actorUserID, action, resource, targetID, path, method,
		statusCode, succ, createdAtUnix,
	)
}

// CanonicalLegalHoldEvent возвращает v1 canonical для legal_hold_events row.
// metadata_json исключена — advisory, не core evidence field.
func CanonicalLegalHoldEvent(
	id, holdID, action, newStatus, actorID string,
	createdAtUnix int64,
) string {
	return fmt.Sprintf("v1|%s|%s|%s|%s|%s|%d",
		id, holdID, action, newStatus, actorID, createdAtUnix,
	)
}

// CostMicrocents конвертирует float64 USD в int64 microcents для canonical.
// 1 USD = 1_000_000 microcents. Rounding: nearest integer.
func CostMicrocents(costUSD float64) int64 {
	return int64(costUSD*1_000_000 + 0.5)
}

// sortedJoin сортирует slice и объединяет через запятую.
// nil/empty → "".
func sortedJoin(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	c := make([]string, len(ss))
	copy(c, ss)
	sort.Strings(c)
	return strings.Join(c, ",")
}

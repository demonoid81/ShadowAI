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

// CanonicalAuditLogV2 returns v2 canonical including org_id (PR-T2.3).
// Format: "v2|<fields>|<org_id>" — distinct v2| prefix, not built on v1 string.
// A DBA changing org_id on a v2 row will break the chain; v1 rows remain valid.
func CanonicalAuditLogV2(
	id, userID, model, provider, endpoint string,
	statusCode, promptTokens, completionTokens, totalTokens int,
	costMicrocents int64,
	piiDetected bool,
	piiTypes []string,
	policyAction, outcome, fallbackReason, usageSource string,
	createdAtUnix int64,
	orgID string,
) string {
	piiDet := "0"
	if piiDetected {
		piiDet = "1"
	}
	sortedPII := sortedJoin(piiTypes)
	return fmt.Sprintf("v2|%s|%s|%s|%s|%s|%d|%d|%d|%d|%d|%s|%s|%s|%s|%s|%s|%d|%s",
		id, userID, model, provider, endpoint,
		statusCode, promptTokens, completionTokens, totalTokens,
		costMicrocents,
		piiDet, sortedPII,
		policyAction, outcome, fallbackReason, usageSource,
		createdAtUnix, orgID,
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

// CanonicalAdminEventLogV2 returns v2 canonical including tenant columns (PR-T2.3).
// Format: "v2|<fields>|<org_id>|<source_org_id>|<target_org_id>" — distinct v2| prefix.
func CanonicalAdminEventLogV2(
	id, actorUserID, action, resource, targetID, path, method string,
	statusCode int,
	success bool,
	createdAtUnix int64,
	orgID, sourceOrgID, targetOrgID string,
) string {
	succ := "0"
	if success {
		succ = "1"
	}
	return fmt.Sprintf("v2|%s|%s|%s|%s|%s|%s|%s|%d|%s|%d|%s|%s|%s",
		id, actorUserID, action, resource, targetID, path, method,
		statusCode, succ, createdAtUnix,
		orgID, sourceOrgID, targetOrgID,
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

// CanonicalAuditPurgeRun возвращает v1 canonical для audit_purge_runs row.
// Пишется ПЕРЕД самим purge в той же tx — доказывает что purge авторизован.
func CanonicalAuditPurgeRun(
	id string,
	cutoffEpoch int64,
	rowsDeleted int,
	target string,
	completedAtEpoch int64,
) string {
	return fmt.Sprintf("v1|%s|%d|%d|%s|%d",
		id, cutoffEpoch, rowsDeleted, target, completedAtEpoch,
	)
}

// CanonicalAuditPurgeRunV2 returns v2 canonical including org_id and scope (PR-T2.4).
// Format: "v2|<id>|<cutoff>|<rowsDeleted>|<target>|<completedAt>|<orgID>|<scope>"
// scope is 'org' or 'global'; orgID is the org being purged or DefaultOrgID for global.
func CanonicalAuditPurgeRunV2(
	id string,
	cutoffEpoch int64,
	rowsDeleted int,
	target string,
	completedAtEpoch int64,
	orgID, scope string,
) string {
	return fmt.Sprintf("v2|%s|%d|%d|%s|%d|%s|%s",
		id, cutoffEpoch, rowsDeleted, target, completedAtEpoch, orgID, scope,
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

// report.go — SOC2.3: Access review report types and DB collection.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
	"time"
)

// buildCommit returns the VCS revision from build info.
func buildCommit() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				if len(s.Value) > 12 {
					return s.Value[:12]
				}
				return s.Value
			}
		}
	}
	return ""
}

// ── Report manifest ────────────────────────────────────────────────────────

type Manifest struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	Period        Period    `json:"period"`
	Scope         string    `json:"scope"`   // "org" | "global"
	OrgID         string    `json:"org_id,omitempty"`
	BuildCommit   string    `json:"build_commit,omitempty"`
}

type Period struct {
	From string `json:"from"` // YYYY-MM-DD
	To   string `json:"to"`   // YYYY-MM-DD
}

// ── User entries ───────────────────────────────────────────────────────────

// UserEntry holds access-review-relevant fields.
// NEVER includes raw secrets: no Password, APIKey plaintext, TOTPSecret, OIDCSubject.
// OIDCIssuer (the IdP URL) is included; OIDCSubject is masked as a truncated hash.
type UserEntry struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Role         string    `json:"role"`
	OrgID        string    `json:"org_id"`
	IsActive     bool      `json:"is_active"`
	MFARequired  bool      `json:"mfa_required"`
	HasTOTP      bool      `json:"has_totp"` // totp_secret IS NOT NULL — no raw secret
	OIDCIssuer   string    `json:"oidc_issuer,omitempty"`
	// OIDCSubjectHash: SHA256(subject)[:16] — identifies IdP linkage without raw subject.
	OIDCSubjectHash string `json:"oidc_subject_hash,omitempty"`
	OIDCLinked   bool      `json:"oidc_linked"`
	SCIMLinked   bool      `json:"scim_linked"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ── Break-glass events ─────────────────────────────────────────────────────

type BreakGlassEvent struct {
	EventID     string    `json:"event_id"`
	ActorUserID string    `json:"actor_user_id,omitempty"`
	Action      string    `json:"action"`
	OrgID       string    `json:"org_id,omitempty"`
	SourceOrgID string    `json:"source_org_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// ── Findings ───────────────────────────────────────────────────────────────

type FindingCode string

const (
	FindingGlobalAdminPresent  FindingCode = "global_admin_present"
	FindingAdminWithoutMFA     FindingCode = "admin_without_mfa"
	FindingBreakGlassUsed      FindingCode = "break_glass_used"
	FindingInactivePrivileged  FindingCode = "inactive_privileged"
	FindingUnlinkedAdmin       FindingCode = "unlinked_admin"
)

type Finding struct {
	Code        FindingCode `json:"code"`
	Severity    string      `json:"severity"` // "critical" | "high" | "medium" | "informational"
	Description string      `json:"description"`
	UserIDs     []string    `json:"user_ids,omitempty"` // affected users
	Count       int         `json:"count"`
	Remediation string      `json:"remediation"`
}

// ── Summary ────────────────────────────────────────────────────────────────

type UsersSummary struct {
	Total        int `json:"total"`
	Active       int `json:"active"`
	Inactive     int `json:"inactive"`
	Admins       int `json:"admins"`
	GlobalAdmins int `json:"global_admins"`
	WithMFA      int `json:"with_mfa"`
	OIDCLinked   int `json:"oidc_linked"`
	SCIMLinked   int `json:"scim_linked"`
	Unlinked     int `json:"unlinked"`
}

// ── Full report ────────────────────────────────────────────────────────────

type AccessReviewReport struct {
	Manifest         Manifest          `json:"manifest"`
	UsersSummary     UsersSummary      `json:"users_summary"`
	PrivilegedUsers  []UserEntry       `json:"privileged_users"`
	GlobalAdmins     []UserEntry       `json:"global_admins"`
	OrgAdmins        []UserEntry       `json:"org_admins"`
	AdminsWithoutMFA []UserEntry       `json:"admins_without_mfa"`
	OIDCLinked       []UserEntry       `json:"oidc_linked_users"`
	SCIMLinked       []UserEntry       `json:"scim_linked_users"`
	UnlinkedUsers    []UserEntry       `json:"unlinked_users"`
	InactiveUsers    []UserEntry       `json:"inactive_users"`
	BreakGlassEvents []BreakGlassEvent `json:"break_glass_events"`
	Findings         []Finding         `json:"findings"`
}

// ── DB collection ──────────────────────────────────────────────────────────

// CollectConfig parameterises the report collection.
type CollectConfig struct {
	OrgID           string // empty = global
	IsGlobal        bool
	From            time.Time
	To              time.Time
	RequireAdminMFA bool
	RequireIDPLink  bool
}

// Collect queries the DB and builds the report.
func Collect(ctx context.Context, db *sql.DB, cfg CollectConfig) (*AccessReviewReport, error) {
	users, err := collectUsers(ctx, db, cfg.OrgID)
	if err != nil {
		return nil, fmt.Errorf("collect users: %w", err)
	}

	bgEvents, err := collectBreakGlassEvents(ctx, db, cfg.OrgID, cfg.From, cfg.To)
	if err != nil {
		return nil, fmt.Errorf("collect break-glass events: %w", err)
	}

	report := buildReport(cfg, users, bgEvents)
	return report, nil
}

// collectUsers queries users with all access-review-relevant fields.
func collectUsers(ctx context.Context, db *sql.DB, orgID string) ([]UserEntry, error) {
	const baseQuery = `
SELECT id, email, role,
       COALESCE(org_id::text, '00000000-0000-0000-0000-000000000001') AS org_id,
       is_active, mfa_required,
       totp_secret IS NOT NULL AS has_totp,
       COALESCE(oidc_issuer, '') AS oidc_issuer,
       COALESCE(oidc_subject, '') AS oidc_subject,
       scim_external_id IS NOT NULL AS scim_linked,
       created_at, updated_at
FROM users`

	var (
		rows *sql.Rows
		err  error
	)
	if orgID == "" {
		rows, err = db.QueryContext(ctx, baseQuery+" ORDER BY email")
	} else {
		rows, err = db.QueryContext(ctx, baseQuery+" WHERE org_id = $1 ORDER BY email", orgID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []UserEntry
	for rows.Next() {
		var u UserEntry
		var oidcSubject string
		if err := rows.Scan(
			&u.ID, &u.Email, &u.Role, &u.OrgID,
			&u.IsActive, &u.MFARequired, &u.HasTOTP,
			&u.OIDCIssuer, &oidcSubject, &u.SCIMLinked,
			&u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, err
		}
		u.OIDCLinked = u.OIDCIssuer != ""
		if oidcSubject != "" {
			// Mask: SHA256(subject) first 16 hex chars — identifies linkage without raw subject.
			h := sha256.Sum256([]byte(oidcSubject))
			u.OIDCSubjectHash = hex.EncodeToString(h[:])[:16]
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// collectBreakGlassEvents queries admin_event_logs for events with break_glass=true.
func collectBreakGlassEvents(ctx context.Context, db *sql.DB, orgID string, from, to time.Time) ([]BreakGlassEvent, error) {
	// Break-glass events store break_glass=true in metadata_json.
	// We use PostgreSQL JSON operator to filter. Non-JSONB DBs: skip gracefully.
	var (
		rows *sql.Rows
		err  error
	)
	const selectCols = `id, COALESCE(actor_user_id::text,''), action,
	                    COALESCE(org_id::text,''), COALESCE(source_org_id::text,''),
	                    created_at`
	const fromAdminEvents = ` FROM admin_event_logs
	                          WHERE metadata_json::jsonb->>'break_glass' = 'true'
	                            AND created_at >= $1 AND created_at <= $2`

	if orgID == "" {
		rows, err = db.QueryContext(ctx,
			"SELECT "+selectCols+fromAdminEvents+" ORDER BY created_at DESC",
			from, to)
	} else {
		rows, err = db.QueryContext(ctx,
			"SELECT "+selectCols+fromAdminEvents+
				" AND (org_id = $3 OR source_org_id = $3 OR target_org_id = $3)"+
				" ORDER BY created_at DESC",
			from, to, orgID)
	}
	if err != nil {
		// If JSONB operator is not supported (non-Postgres or old version), return empty.
		if strings.Contains(err.Error(), "jsonb") || strings.Contains(err.Error(), "operator") {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()

	var events []BreakGlassEvent
	for rows.Next() {
		var e BreakGlassEvent
		if err := rows.Scan(&e.EventID, &e.ActorUserID, &e.Action,
			&e.OrgID, &e.SourceOrgID, &e.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// buildReport assembles the full report from collected data.
func buildReport(cfg CollectConfig, users []UserEntry, bgEvents []BreakGlassEvent) *AccessReviewReport {
	scope := "org"
	if cfg.IsGlobal {
		scope = "global"
	}

	r := &AccessReviewReport{
		Manifest: Manifest{
			SchemaVersion: "1",
			GeneratedAt:   time.Now().UTC(),
			Period:        Period{From: cfg.From.Format("2006-01-02"), To: cfg.To.Format("2006-01-02")},
			Scope:         scope,
			OrgID:         cfg.OrgID,
			BuildCommit:   buildCommit(),
		},
		BreakGlassEvents: bgEvents,
	}

	// Classify users.
	var (
		privileged      []UserEntry
		globalAdmins    []UserEntry
		orgAdmins       []UserEntry
		adminNoMFA      []UserEntry
		oidcLinked      []UserEntry
		scimLinked      []UserEntry
		unlinked        []UserEntry
		inactive        []UserEntry
	)

	summary := UsersSummary{}
	for _, u := range users {
		summary.Total++
		if u.IsActive {
			summary.Active++
		} else {
			summary.Inactive++
			inactive = append(inactive, u)
		}

		isAdmin := u.Role == "admin" || u.Role == "global_admin"
		if isAdmin {
			summary.Admins++
		}
		if u.Role == "global_admin" {
			summary.GlobalAdmins++
			globalAdmins = append(globalAdmins, u)
		}
		if u.Role == "admin" {
			orgAdmins = append(orgAdmins, u)
		}
		if u.Role == "admin" || u.Role == "global_admin" {
			privileged = append(privileged, u)
		}

		// MFA.
		mfaOK := u.MFARequired && u.HasTOTP
		if mfaOK {
			summary.WithMFA++
		}
		if isAdmin && (!u.MFARequired || !u.HasTOTP) {
			adminNoMFA = append(adminNoMFA, u)
		}

		// IdP linkage.
		if u.OIDCLinked {
			summary.OIDCLinked++
			oidcLinked = append(oidcLinked, u)
		}
		if u.SCIMLinked {
			summary.SCIMLinked++
			scimLinked = append(scimLinked, u)
		}
		if !u.OIDCLinked && !u.SCIMLinked {
			summary.Unlinked++
			unlinked = append(unlinked, u)
		}
	}

	r.UsersSummary = summary
	r.PrivilegedUsers = coalesceNil(privileged)
	r.GlobalAdmins = coalesceNil(globalAdmins)
	r.OrgAdmins = coalesceNil(orgAdmins)
	r.AdminsWithoutMFA = coalesceNil(adminNoMFA)
	r.OIDCLinked = coalesceNil(oidcLinked)
	r.SCIMLinked = coalesceNil(scimLinked)
	r.UnlinkedUsers = coalesceNil(unlinked)
	r.InactiveUsers = coalesceNil(inactive)

	// Build findings.
	r.Findings = buildFindings(r, cfg)
	return r
}

func buildFindings(r *AccessReviewReport, cfg CollectConfig) []Finding {
	var findings []Finding

	// global_admin_present (conservative default: always a finding).
	if len(r.GlobalAdmins) > 0 {
		ids := userIDs(r.GlobalAdmins)
		findings = append(findings, Finding{
			Code:        FindingGlobalAdminPresent,
			Severity:    "high",
			Description: fmt.Sprintf("%d global_admin account(s) present; review necessity", len(r.GlobalAdmins)),
			UserIDs:     ids,
			Count:       len(r.GlobalAdmins),
			Remediation: "Review each global_admin account. Remove or disable if no longer required. " +
				"Global admin bypasses tenant isolation — minimize to operational necessity.",
		})
	}

	// admin_without_mfa (when --require-admin-mfa or always report).
	if cfg.RequireAdminMFA && len(r.AdminsWithoutMFA) > 0 {
		ids := userIDs(r.AdminsWithoutMFA)
		findings = append(findings, Finding{
			Code:        FindingAdminWithoutMFA,
			Severity:    "critical",
			Description: fmt.Sprintf("%d admin(s) lack required MFA (--require-admin-mfa policy)", len(r.AdminsWithoutMFA)),
			UserIDs:     ids,
			Count:       len(r.AdminsWithoutMFA),
			Remediation: "Require TOTP enrollment for all admin accounts. " +
				"Disable accounts that cannot enroll within policy window.",
		})
	} else if !cfg.RequireAdminMFA && len(r.AdminsWithoutMFA) > 0 {
		// Informational when policy not enforced.
		ids := userIDs(r.AdminsWithoutMFA)
		findings = append(findings, Finding{
			Code:        FindingAdminWithoutMFA,
			Severity:    "medium",
			Description: fmt.Sprintf("%d admin(s) do not have MFA enrolled (informational; use --require-admin-mfa to enforce)", len(r.AdminsWithoutMFA)),
			UserIDs:     ids,
			Count:       len(r.AdminsWithoutMFA),
			Remediation: "Enable --require-admin-mfa policy and enforce TOTP enrollment.",
		})
	}

	// break_glass_used (always a finding if any events in period).
	if len(r.BreakGlassEvents) > 0 {
		actors := make([]string, 0, len(r.BreakGlassEvents))
		seen := map[string]bool{}
		for _, e := range r.BreakGlassEvents {
			if e.ActorUserID != "" && !seen[e.ActorUserID] {
				actors = append(actors, e.ActorUserID)
				seen[e.ActorUserID] = true
			}
		}
		findings = append(findings, Finding{
			Code:        FindingBreakGlassUsed,
			Severity:    "high",
			Description: fmt.Sprintf("%d break-glass event(s) in period; emergency access was used", len(r.BreakGlassEvents)),
			UserIDs:     actors,
			Count:       len(r.BreakGlassEvents),
			Remediation: "Review each break-glass use: verify authorization, rotate credentials, " +
				"document incident. Break-glass must always be reviewed and acknowledged by security team.",
		})
	}

	// inactive_privileged.
	var inactivePrivileged []string
	for _, u := range r.InactiveUsers {
		if u.Role == "admin" || u.Role == "global_admin" {
			inactivePrivileged = append(inactivePrivileged, u.ID)
		}
	}
	if len(inactivePrivileged) > 0 {
		findings = append(findings, Finding{
			Code:        FindingInactivePrivileged,
			Severity:    "critical",
			Description: fmt.Sprintf("%d inactive user(s) with privileged role", len(inactivePrivileged)),
			UserIDs:     inactivePrivileged,
			Count:       len(inactivePrivileged),
			Remediation: "Remove privileged role from inactive accounts or deprovision permanently. " +
				"Inactive privileged accounts are a persistent access risk.",
		})
	}

	// unlinked_admin (only when --require-idp-link).
	if cfg.RequireIDPLink {
		var unlinkedAdmins []string
		for _, u := range r.UnlinkedUsers {
			if u.Role == "admin" || u.Role == "global_admin" {
				unlinkedAdmins = append(unlinkedAdmins, u.ID)
			}
		}
		if len(unlinkedAdmins) > 0 {
			findings = append(findings, Finding{
				Code:        FindingUnlinkedAdmin,
				Severity:    "high",
				Description: fmt.Sprintf("%d admin(s) without OIDC or SCIM IdP linkage (--require-idp-link policy)", len(unlinkedAdmins)),
				UserIDs:     unlinkedAdmins,
				Count:       len(unlinkedAdmins),
				Remediation: "Link admin accounts to the corporate IdP via OIDC or SCIM. " +
					"Unlinked accounts bypass IdP-controlled deprovisioning.",
			})
		}
	}

	if len(findings) == 0 {
		return []Finding{} // always return array, not null
	}
	return findings
}

// ── Helpers ────────────────────────────────────────────────────────────────

func userIDs(users []UserEntry) []string {
	ids := make([]string, len(users))
	for i, u := range users {
		ids[i] = u.ID
	}
	return ids
}

func coalesceNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// PrintTable writes a human-readable summary to w.
func PrintTable(w interface{ WriteString(string) (int, error) }, r *AccessReviewReport) {
	lines := []string{
		fmt.Sprintf("Access Review Report — scope=%s  period=%s to %s  generated=%s",
			r.Manifest.Scope,
			r.Manifest.Period.From, r.Manifest.Period.To,
			r.Manifest.GeneratedAt.Format("2006-01-02T15:04:05Z")),
		"",
		fmt.Sprintf("Users: total=%d  active=%d  inactive=%d  admins=%d  global_admins=%d",
			r.UsersSummary.Total, r.UsersSummary.Active, r.UsersSummary.Inactive,
			r.UsersSummary.Admins, r.UsersSummary.GlobalAdmins),
		fmt.Sprintf("       with_mfa=%d  oidc_linked=%d  scim_linked=%d  unlinked=%d",
			r.UsersSummary.WithMFA, r.UsersSummary.OIDCLinked, r.UsersSummary.SCIMLinked, r.UsersSummary.Unlinked),
		fmt.Sprintf("Break-glass events in period: %d", len(r.BreakGlassEvents)),
		"",
		"Findings:",
	}
	if len(r.Findings) == 0 {
		lines = append(lines, "  (none — review clean)")
	}
	for _, f := range r.Findings {
		lines = append(lines, fmt.Sprintf("  [%s] %s  severity=%s  count=%d",
			f.Code, f.Description, f.Severity, f.Count))
		lines = append(lines, fmt.Sprintf("    remediation: %s", f.Remediation))
	}
	for _, l := range lines {
		w.WriteString(l + "\n")
	}
}

// marshalReport serialises the report to indented JSON.
func marshalReport(r *AccessReviewReport) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

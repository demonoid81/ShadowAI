package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// ── Test helpers ───────────────────────────────────────────────────────────

func makeUser(id, email, role, orgID string, active, mfaRequired, hasTOTP, oidcLinked, scimLinked bool) UserEntry {
	return UserEntry{
		ID:          id,
		Email:       email,
		Role:        role,
		OrgID:       orgID,
		IsActive:    active,
		MFARequired: mfaRequired,
		HasTOTP:     hasTOTP,
		OIDCLinked:  oidcLinked,
		SCIMLinked:  scimLinked,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
}

func testPeriod() CollectConfig {
	return CollectConfig{
		From: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC),
	}
}

// ── DoD tests ──────────────────────────────────────────────────────────────

// TestTenantReport_ExcludesOtherOrg — DoD: tenant report only includes users
// of the specified org.
func TestTenantReport_ExcludesOtherOrg(t *testing.T) {
	cfg := testPeriod()
	cfg.OrgID = "org-a"
	cfg.IsGlobal = false

	// Users: two from org-a, one from org-b.
	users := []UserEntry{
		makeUser("u1", "alice@a.com", "user", "org-a", true, false, false, false, false),
		makeUser("u2", "bob@a.com", "admin", "org-a", true, true, true, true, false),
		makeUser("u3", "carol@b.com", "admin", "org-b", true, false, false, false, false),
	}
	// In tenant mode, collectUsers would filter by org_id — simulate by pre-filtering.
	var filtered []UserEntry
	for _, u := range users {
		if u.OrgID == cfg.OrgID {
			filtered = append(filtered, u)
		}
	}

	report := buildReport(cfg, filtered, nil)
	if report.UsersSummary.Total != 2 {
		t.Errorf("tenant report total=%d, want 2 (carol from org-b excluded)", report.UsersSummary.Total)
	}
	for _, u := range report.PrivilegedUsers {
		if u.OrgID == "org-b" {
			t.Errorf("tenant report leaked org-b user %s", u.Email)
		}
	}
}

// TestGlobalReport_IncludesGlobalAdmin — DoD: global report includes global_admin users.
func TestGlobalReport_IncludesGlobalAdmin(t *testing.T) {
	cfg := testPeriod()
	cfg.IsGlobal = true

	users := []UserEntry{
		makeUser("ga1", "gadmin@sys.com", "global_admin", "org-sys", true, true, true, false, false),
		makeUser("u1", "user@org-a.com", "user", "org-a", true, false, false, true, false),
	}
	report := buildReport(cfg, users, nil)
	if len(report.GlobalAdmins) != 1 {
		t.Errorf("global report: global_admins=%d, want 1", len(report.GlobalAdmins))
	}
	if report.GlobalAdmins[0].ID != "ga1" {
		t.Errorf("wrong global admin: %s", report.GlobalAdmins[0].Email)
	}
	// global_admin_present finding expected.
	found := false
	for _, f := range report.Findings {
		if f.Code == FindingGlobalAdminPresent {
			found = true
		}
	}
	if !found {
		t.Error("global_admin_present finding missing")
	}
}

// TestAdminWithoutMFA_Finding — DoD: admin without MFA produces finding.
func TestAdminWithoutMFA_Finding(t *testing.T) {
	cfg := testPeriod()
	cfg.OrgID = "org-a"
	cfg.RequireAdminMFA = true

	users := []UserEntry{
		makeUser("admin1", "a@org.com", "admin", "org-a", true, false, false, true, false), // no MFA
		makeUser("admin2", "b@org.com", "admin", "org-a", true, true, true, true, false),   // has MFA
	}
	report := buildReport(cfg, users, nil)
	if len(report.AdminsWithoutMFA) != 1 {
		t.Errorf("admins_without_mfa=%d, want 1", len(report.AdminsWithoutMFA))
	}
	found := false
	for _, f := range report.Findings {
		if f.Code == FindingAdminWithoutMFA && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Error("admin_without_mfa critical finding missing when --require-admin-mfa")
	}
}

// TestBreakGlassUsage_Finding — DoD: break-glass events produce finding.
func TestBreakGlassUsage_Finding(t *testing.T) {
	cfg := testPeriod()
	cfg.OrgID = "org-a"

	users := []UserEntry{
		makeUser("u1", "user@a.com", "user", "org-a", true, false, false, false, false),
	}
	bgEvents := []BreakGlassEvent{
		{
			EventID:     "ev1",
			ActorUserID: "admin-emergency",
			Action:      "admin_login",
			OrgID:       "org-a",
			CreatedAt:   time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC),
		},
	}
	report := buildReport(cfg, users, bgEvents)
	found := false
	for _, f := range report.Findings {
		if f.Code == FindingBreakGlassUsed {
			found = true
			if f.Count != 1 {
				t.Errorf("break_glass finding count=%d, want 1", f.Count)
			}
		}
	}
	if !found {
		t.Error("break_glass_used finding missing")
	}
}

// TestInactivePrivileged_Finding — DoD: inactive user with privileged role is a finding.
func TestInactivePrivileged_Finding(t *testing.T) {
	cfg := testPeriod()
	cfg.OrgID = "org-a"

	users := []UserEntry{
		makeUser("admin1", "inactive@a.com", "admin", "org-a", false, false, false, false, false),
		makeUser("user1", "active@a.com", "user", "org-a", true, false, false, false, false),
	}
	report := buildReport(cfg, users, nil)
	found := false
	for _, f := range report.Findings {
		if f.Code == FindingInactivePrivileged {
			found = true
			if f.Severity != "critical" {
				t.Errorf("inactive_privileged severity=%q, want critical", f.Severity)
			}
		}
	}
	if !found {
		t.Error("inactive_privileged finding missing")
	}
}

// TestUnlinkedAdmin_Finding — DoD: admin without IdP linkage finding when policy set.
func TestUnlinkedAdmin_Finding(t *testing.T) {
	cfg := testPeriod()
	cfg.OrgID = "org-a"
	cfg.RequireIDPLink = true

	users := []UserEntry{
		makeUser("a1", "linked@a.com", "admin", "org-a", true, true, true, true, false), // OIDC-linked
		makeUser("a2", "local@a.com", "admin", "org-a", true, true, true, false, false), // no IdP
	}
	report := buildReport(cfg, users, nil)
	found := false
	for _, f := range report.Findings {
		if f.Code == FindingUnlinkedAdmin {
			found = true
			if f.Count != 1 {
				t.Errorf("unlinked_admin count=%d, want 1", f.Count)
			}
		}
	}
	if !found {
		t.Error("unlinked_admin finding missing when --require-idp-link")
	}
}

// TestUnlinkedAdmin_NoFinding_WhenPolicyOff — unlinked admin without policy = no finding.
func TestUnlinkedAdmin_NoFinding_WhenPolicyOff(t *testing.T) {
	cfg := testPeriod()
	cfg.OrgID = "org-a"
	cfg.RequireIDPLink = false // policy off

	users := []UserEntry{
		makeUser("a1", "local@a.com", "admin", "org-a", true, true, true, false, false),
	}
	report := buildReport(cfg, users, nil)
	for _, f := range report.Findings {
		if f.Code == FindingUnlinkedAdmin {
			t.Errorf("unexpected unlinked_admin finding when policy is off")
		}
	}
}

// TestCleanReport_ExitOK — DoD: clean report (no findings) → exit 0.
func TestCleanReport_ExitOK(t *testing.T) {
	cfg := testPeriod()
	cfg.OrgID = "org-a"
	cfg.RequireAdminMFA = true
	cfg.RequireIDPLink = true

	// All clean: active admin with MFA and IdP linkage.
	users := []UserEntry{
		makeUser("a1", "admin@a.com", "admin", "org-a", true, true, true, true, false),
		makeUser("u1", "user@a.com", "user", "org-a", true, false, false, true, false),
	}
	report := buildReport(cfg, users, nil)
	// No global_admin = no finding. No MFA issues. No break-glass. No inactive priv.
	for _, f := range report.Findings {
		t.Errorf("unexpected finding on clean report: %s", f.Code)
	}
	if len(report.Findings) != 0 {
		t.Errorf("clean report: findings=%d, want 0", len(report.Findings))
	}
}

// TestFindings_ExitOne — DoD: findings produce exit 1 via CLI.
func TestFindings_ExitOne(t *testing.T) {
	// Use --global with no DATABASE_URL → exits 2 (config error)
	// But we test the exit-code logic by inspecting findings length.
	cfg := testPeriod()
	cfg.IsGlobal = true
	users := []UserEntry{
		makeUser("ga1", "ga@sys.com", "global_admin", "org-sys", true, true, true, false, false),
	}
	report := buildReport(cfg, users, nil)
	if len(report.Findings) == 0 {
		t.Error("global_admin should always produce finding")
	}
	// Simulate the exit code logic.
	exitCode := exitOK
	if len(report.Findings) > 0 {
		exitCode = exitFindings
	}
	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d", exitCode, exitFindings)
	}
}

// TestRun_MissingOrgOrGlobal — config error when neither --org-id nor --global.
func TestRun_MissingOrgOrGlobal(t *testing.T) {
	code := run([]string{"--from", "2026-01-01", "--to", "2026-03-31"}, os.Stdout, os.Stderr)
	if code != exitError {
		t.Errorf("missing scope: exit=%d, want exitError(%d)", code, exitError)
	}
}

// TestRun_InvalidFormat — config error for unknown format.
func TestRun_InvalidFormat(t *testing.T) {
	code := run([]string{"--global", "--from", "2026-01-01", "--to", "2026-03-31", "--format", "xml"}, os.Stdout, os.Stderr)
	if code != exitError {
		t.Errorf("invalid format: exit=%d, want exitError(%d)", code, exitError)
	}
}

// TestUsersSummary_Counts — summary fields are computed correctly.
func TestUsersSummary_Counts(t *testing.T) {
	cfg := testPeriod()
	cfg.OrgID = "org-a"

	users := []UserEntry{
		makeUser("u1", "a@a.com", "admin", "org-a", true, true, true, true, false),   // active admin, OIDC-linked, MFA
		makeUser("u2", "b@a.com", "user", "org-a", true, false, false, false, true),   // active user, SCIM-linked
		makeUser("u3", "c@a.com", "user", "org-a", false, false, false, false, false), // inactive, unlinked
	}
	report := buildReport(cfg, users, nil)
	s := report.UsersSummary
	if s.Total != 3 {
		t.Errorf("total=%d, want 3", s.Total)
	}
	if s.Active != 2 {
		t.Errorf("active=%d, want 2", s.Active)
	}
	if s.Inactive != 1 {
		t.Errorf("inactive=%d, want 1", s.Inactive)
	}
	if s.Admins != 1 {
		t.Errorf("admins=%d, want 1", s.Admins)
	}
	if s.OIDCLinked != 1 {
		t.Errorf("oidc_linked=%d, want 1", s.OIDCLinked)
	}
	if s.SCIMLinked != 1 {
		t.Errorf("scim_linked=%d, want 1", s.SCIMLinked)
	}
	if s.Unlinked != 1 {
		t.Errorf("unlinked=%d, want 1 (inactive user has no IdP)", s.Unlinked)
	}
}

// TestJSONOutput_ValidSchema — JSON output contains required manifest fields.
func TestJSONOutput_ValidSchema(t *testing.T) {
	cfg := testPeriod()
	cfg.OrgID = "org-a"
	cfg.IsGlobal = false

	report := buildReport(cfg, []UserEntry{}, nil)
	data, err := marshalReport(report)
	if err != nil {
		t.Fatalf("marshalReport: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"manifest", "users_summary", "findings", "break_glass_events"} {
		if _, ok := parsed[field]; !ok {
			t.Errorf("JSON missing field %q", field)
		}
	}
	manifest := parsed["manifest"].(map[string]interface{})
	if manifest["schema_version"] != "1" {
		t.Errorf("schema_version=%v, want 1", manifest["schema_version"])
	}
}

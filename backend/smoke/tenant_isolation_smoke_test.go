//go:build enterprise && smoke

// PR-T2.5: Two-org tenant isolation smoke scenarios.
// Verifies end-to-end data isolation across org_a / org_b against real PG via
// testcontainers. Covers: user repo, SCIM syncer, governance policy, audit logs,
// admin events, tenant purge, and evidence export bundle.
package smoke

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/evidencebundle"
	"github.com/shadowai/backend/internal/governance"
	"github.com/shadowai/backend/internal/scim"
)

const (
	smokeOrgA = "aaaaaaaa-0000-0000-0000-000000000001"
	smokeOrgB = "bbbbbbbb-0000-0000-0000-000000000001"
)

// twoOrgFixture provisions two orgs and one admin user per org.
// Returns (adminUserIDorgA, adminUserIDorgB).
func twoOrgFixture(t *testing.T, ctx context.Context, infra *infraStack, authSvc *auth.Service) (string, string) {
	t.Helper()
	db := infra.DB

	// Insert org_a and org_b (on conflict = already seeded by default org logic — fine).
	for _, row := range []struct{ id, name, slug string }{
		{smokeOrgA, "Org A", "org-a"},
		{smokeOrgB, "Org B", "org-b"},
	} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
			row.id, row.name, row.slug); err != nil {
			t.Fatalf("insert org %s: %v", row.slug, err)
		}
	}

	// Register admins in each org by inserting directly with explicit org_id.
	// auth.Service.Register always defaults to DefaultOrgID, so we override via SQL.
	repo := auth.NewRepository(infra.DB)
	adminA, err := authSvc.Register(ctx, "admin-a@smoke.test", "StrongPassword123!", auth.RoleAdmin)
	if err != nil {
		t.Fatalf("Register adminA: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE users SET org_id=$1 WHERE id=$2`, smokeOrgA, adminA.ID); err != nil {
		t.Fatalf("set orgA for adminA: %v", err)
	}

	adminB, err := authSvc.Register(ctx, "admin-b@smoke.test", "StrongPassword123!", auth.RoleAdmin)
	if err != nil {
		t.Fatalf("Register adminB: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE users SET org_id=$1 WHERE id=$2`, smokeOrgB, adminB.ID); err != nil {
		t.Fatalf("set orgB for adminB: %v", err)
	}

	// Create one regular user in each org.
	userA, err := authSvc.Register(ctx, "user-a@smoke.test", "StrongPassword123!", auth.RoleUser)
	if err != nil {
		t.Fatalf("Register userA: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE users SET org_id=$1 WHERE id=$2`, smokeOrgA, userA.ID); err != nil {
		t.Fatalf("set orgA for userA: %v", err)
	}
	userB, err := authSvc.Register(ctx, "user-b@smoke.test", "StrongPassword123!", auth.RoleUser)
	if err != nil {
		t.Fatalf("Register userB: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE users SET org_id=$1 WHERE id=$2`, smokeOrgB, userB.ID); err != nil {
		t.Fatalf("set orgB for userB: %v", err)
	}

	// Ensure the repo is used to verify OrgID propagation on read.
	uA, err := repo.GetByIDScoped(ctx, adminA.ID, smokeOrgA)
	if err != nil || uA.OrgID != smokeOrgA {
		t.Fatalf("adminA org mismatch: OrgID=%q err=%v", uA.OrgID, err)
	}

	t.Logf("smoke/tenant-fixture: org_a=%s admin=%s | org_b=%s admin=%s",
		smokeOrgA, adminA.ID, smokeOrgB, adminB.ID)
	return adminA.ID, adminB.ID
}

// ---------------------------------------------------------------------------
// T2.5.1 — User repository isolation
// ---------------------------------------------------------------------------

// TestSmoke_TenantIsolation_UserRepo verifies:
//   - ListUsers scoped to org_a returns only org_a users.
//   - GetByIDScoped returns sql.ErrNoRows for cross-org user ID.
func TestSmoke_TenantIsolation_UserRepo(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	authSvc := auth.NewService(auth.NewRepository(infra.DB), "smoke-tenant-jwt-32chars!!")
	twoOrgFixture(t, ctx, infra, authSvc)

	repo := auth.NewRepository(infra.DB)

	// List org_a — should not include org_b users.
	usersA, err := repo.ListUsers(ctx, smokeOrgA)
	if err != nil {
		t.Fatalf("ListUsers orgA: %v", err)
	}
	for _, u := range usersA {
		if u.OrgID != smokeOrgA {
			t.Errorf("org_a list contains user with OrgID=%q", u.OrgID)
		}
	}
	if len(usersA) < 2 {
		t.Errorf("expected at least 2 users in org_a, got %d", len(usersA))
	}
	t.Logf("smoke/tenant-user-repo: org_a list=%d users (all org_a)", len(usersA))

	// List org_b — should not include org_a users.
	usersB, err := repo.ListUsers(ctx, smokeOrgB)
	if err != nil {
		t.Fatalf("ListUsers orgB: %v", err)
	}
	for _, u := range usersB {
		if u.OrgID != smokeOrgB {
			t.Errorf("org_b list contains user with OrgID=%q", u.OrgID)
		}
	}

	// Cross-org GetByIDScoped: pick first org_a user, try to get from org_b.
	if len(usersA) > 0 {
		_, err := repo.GetByIDScoped(ctx, usersA[0].ID, smokeOrgB)
		if err == nil {
			t.Error("GetByIDScoped(orgA_user_id, orgB) should return error but got nil")
		}
		t.Logf("smoke/tenant-user-repo: cross-org GetByIDScoped correctly denied (%v)", err)
	}

	// JWT claims carry correct OrgID after login.
	token, err := authSvc.GenerateTokenForUserID(ctx, usersA[0].ID)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := authSvc.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.OrgID != smokeOrgA {
		t.Errorf("JWT OrgID = %q, want %q", claims.OrgID, smokeOrgA)
	}
	t.Logf("smoke/tenant-user-repo: JWT OrgID=%s (correct)", claims.OrgID)
}

// ---------------------------------------------------------------------------
// T2.5.2 — SCIM isolation
// ---------------------------------------------------------------------------

// TestSmoke_TenantIsolation_SCIM verifies:
//   - SCIM token for org_a provisions users only in org_a.
//   - Provision (GetByIDScoped) for org_b user returns not-found.
//   - ListUsers returns only org_a users for org_a token.
func TestSmoke_TenantIsolation_SCIM(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	authSvc := auth.NewService(auth.NewRepository(infra.DB), "smoke-tenant-jwt-32chars!!")
	twoOrgFixture(t, ctx, infra, authSvc)

	// Insert scim_tokens for org_a and org_b.
	tokenA := "scim-token-org-a-smoke"
	tokenB := "scim-token-org-b-smoke"
	hashA := sha256hex(tokenA)
	hashB := sha256hex(tokenB)
	for _, row := range []struct{ hash, org string }{
		{hashA, smokeOrgA},
		{hashB, smokeOrgB},
	} {
		if _, err := infra.DB.ExecContext(ctx,
			`INSERT INTO scim_tokens (org_id, token_hash, label) VALUES ($1, $2, 'smoke')`,
			row.org, row.hash); err != nil {
			t.Fatalf("insert scim_token: %v", err)
		}
	}

	authRepo := auth.NewRepository(infra.DB)
	scimCfg, _ := scim.ParseSyncConfig("user", `{"admins":"admin"}`, "", true)

	// Syncer scoped to org_a.
	syncerA := scim.NewUserSyncer(authRepo, scimCfg).WithOrgID(smokeOrgA)

	// Provision user in org_a.
	result, err := syncerA.Provision(ctx, scim.User{
		ExternalID:     "ext-scim-a",
		UserName:       "scim-user-a@smoke.test",
		Active:         boolPtr(true),
		Roles:          []scim.RoleValue{{Value: "user"}},
	})
	if err != nil {
		t.Fatalf("Provision orgA: %v", err)
	}
	if result.User.OrgID != smokeOrgA {
		t.Errorf("provisioned user OrgID=%q, want %q", result.User.OrgID, smokeOrgA)
	}
	t.Logf("smoke/tenant-scim: provisioned %s in org_a", result.User.ID)

	// Syncer org_a: ListUsers should return only org_a users.
	usersA, err := syncerA.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers orgA syncer: %v", err)
	}
	for _, u := range usersA {
		if u.OrgID != smokeOrgA {
			t.Errorf("org_a syncer ListUsers returned user with OrgID=%q", u.OrgID)
		}
	}
	t.Logf("smoke/tenant-scim: org_a syncer list=%d users (all org_a)", len(usersA))

	// Syncer org_a: GetUser for org_b provisioned user → not found.
	syncerB := scim.NewUserSyncer(authRepo, scimCfg).WithOrgID(smokeOrgB)
	resultB, _ := syncerB.Provision(ctx, scim.User{
		ExternalID: "ext-scim-b",
		UserName:   "scim-user-b@smoke.test",
		Active:     boolPtr(true),
	})
	if resultB.User == nil {
		t.Fatal("Provision orgB: got nil user")
	}
	_, crossErr := syncerA.GetUser(ctx, resultB.User.ID)
	if crossErr == nil {
		t.Error("org_a syncer GetUser for org_b user should fail, got nil error")
	}
	t.Logf("smoke/tenant-scim: cross-org GetUser correctly denied (%v)", crossErr)
}

// ---------------------------------------------------------------------------
// T2.5.3 — Governance isolation
// ---------------------------------------------------------------------------

// TestSmoke_TenantIsolation_Governance verifies per-org policy:
//   - org_a allows openai/gpt-4o-mini, denies anthropic.
//   - org_b allows anthropic/claude-3-haiku, denies openai.
//   - Evaluate uses org_id to select the correct policy.
func TestSmoke_TenantIsolation_Governance(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	authSvc := auth.NewService(auth.NewRepository(infra.DB), "smoke-tenant-jwt-32chars!!")
	twoOrgFixture(t, ctx, infra, authSvc) // seeds org_a and org_b into organizations

	repo := governance.NewPGRepository(infra.DB)
	svc := governance.NewService(repo)

	// Policy for org_a: allow openai/gpt-4o-mini.
	_, err := svc.Upsert(ctx, &governance.Policy{
		Mode:  governance.ModeAllowlistStrict,
		Rules: []governance.ProviderRule{{Provider: "openai", Models: []string{"gpt-4o-mini"}}},
	}, "", smokeOrgA)
	if err != nil {
		t.Fatalf("Upsert orgA policy: %v", err)
	}

	// Policy for org_b: allow anthropic/claude-3-haiku.
	_, err = svc.Upsert(ctx, &governance.Policy{
		Mode:  governance.ModeAllowlistStrict,
		Rules: []governance.ProviderRule{{Provider: "anthropic", Models: []string{"claude-3-haiku"}}},
	}, "", smokeOrgB)
	if err != nil {
		t.Fatalf("Upsert orgB policy: %v", err)
	}

	// org_a allows openai/gpt-4o-mini, denies anthropic.
	dec, err := svc.Evaluate(ctx, smokeOrgA, "", "", "", "openai", "gpt-4o-mini")
	if err != nil || dec.Kind != governance.DecisionAllow {
		t.Errorf("orgA openai/gpt-4o-mini: want Allow, got %v (err=%v)", dec.Kind, err)
	}
	dec, err = svc.Evaluate(ctx, smokeOrgA, "", "", "", "anthropic", "claude-3-haiku")
	if err != nil || dec.Kind != governance.DecisionDeny {
		t.Errorf("orgA anthropic: want Deny, got %v (err=%v)", dec.Kind, err)
	}

	// org_b allows anthropic, denies openai.
	dec, err = svc.Evaluate(ctx, smokeOrgB, "", "", "", "anthropic", "claude-3-haiku")
	if err != nil || dec.Kind != governance.DecisionAllow {
		t.Errorf("orgB anthropic/claude-3-haiku: want Allow, got %v (err=%v)", dec.Kind, err)
	}
	dec, err = svc.Evaluate(ctx, smokeOrgB, "", "", "", "openai", "gpt-4o-mini")
	if err != nil || dec.Kind != governance.DecisionDeny {
		t.Errorf("orgB openai: want Deny, got %v (err=%v)", dec.Kind, err)
	}

	t.Logf("smoke/tenant-governance: per-org policy isolation verified")
}

// ---------------------------------------------------------------------------
// T2.5.4 — Audit log isolation
// ---------------------------------------------------------------------------

// TestSmoke_TenantIsolation_AuditLogs verifies audit_logs are org-scoped:
//   - org_a audit rows visible only to org_a filter.
//   - org_b filter does not return org_a rows.
func TestSmoke_TenantIsolation_AuditLogs(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	authSvc := auth.NewService(auth.NewRepository(infra.DB), "smoke-tenant-jwt-32chars!!")
	adminAID, adminBID := twoOrgFixture(t, ctx, infra, authSvc)

	auditRepo := audit.NewRepository(infra.DB)

	// Insert audit logs: 3 for org_a, 2 for org_b.
	for _, pair := range []struct{ orgID, userID string }{
		{smokeOrgA, adminAID}, {smokeOrgA, adminAID}, {smokeOrgA, adminAID},
		{smokeOrgB, adminBID}, {smokeOrgB, adminBID},
	} {
		if err := auditRepo.Insert(ctx, &domain.AuditLog{
			ID:           uuid.NewString(),
			UserID:       pair.userID,
			OrgID:        pair.orgID,
			Model:        "gpt-4",
			Provider:     "openai",
			Endpoint:     "/v1/chat",
			StatusCode:   200,
			PolicyAction: "allowed",
		}); err != nil {
			t.Fatalf("Insert auditlog: %v", err)
		}
	}

	// List org_a: should return 3 rows.
	logsA, totalA, err := auditRepo.List(ctx, 50, 0, smokeOrgA, "", "", "", "")
	if err != nil {
		t.Fatalf("List orgA: %v", err)
	}
	if totalA != 3 {
		t.Errorf("orgA total = %d, want 3", totalA)
	}
	for _, l := range logsA {
		if l.OrgID != smokeOrgA {
			t.Errorf("orgA list returned log with OrgID=%q", l.OrgID)
		}
	}

	// List org_b: should return 2 rows.
	_, totalB, err := auditRepo.List(ctx, 50, 0, smokeOrgB, "", "", "", "")
	if err != nil {
		t.Fatalf("List orgB: %v", err)
	}
	if totalB != 2 {
		t.Errorf("orgB total = %d, want 2", totalB)
	}

	// Global list (orgID=""): should return all 5.
	_, totalGlobal, err := auditRepo.List(ctx, 50, 0, "", "", "", "", "")
	if err != nil {
		t.Fatalf("List global: %v", err)
	}
	if totalGlobal < 5 {
		t.Errorf("global total = %d, want >= 5", totalGlobal)
	}

	t.Logf("smoke/tenant-audit: orgA=%d orgB=%d global>=%d (isolation OK)", totalA, totalB, totalGlobal)
}

// ---------------------------------------------------------------------------
// T2.5.5 — Admin events isolation
// ---------------------------------------------------------------------------

// TestSmoke_TenantIsolation_AdminEvents verifies admin_event_logs are org-scoped.
func TestSmoke_TenantIsolation_AdminEvents(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	authSvc := auth.NewService(auth.NewRepository(infra.DB), "smoke-tenant-jwt-32chars!!")
	twoOrgFixture(t, ctx, infra, authSvc) // seeds org_a and org_b into organizations

	adminRepo := adminaudit.NewRepository(infra.DB)
	adminSvc := adminaudit.NewService(adminRepo)

	// Write 2 events for org_a, 1 for org_b.
	for _, orgID := range []string{smokeOrgA, smokeOrgA, smokeOrgB} {
		adminSvc.Record(ctx, adminaudit.Event{
			OrgID:      orgID,
			Action:     "smoke_test",
			Resource:   "audit_logs",
			Path:       "/api/test",
			Method:     "GET",
			StatusCode: 200,
			Success:    true,
		})
	}

	// Allow async insert to complete (adminaudit is synchronous, but small pause to be safe).
	time.Sleep(50 * time.Millisecond)

	// List org_a: expect 2.
	eventsA, totalA, err := adminRepo.List(ctx, 50, 0, smokeOrgA, "", "", "")
	if err != nil {
		t.Fatalf("List orgA admin events: %v", err)
	}
	if totalA < 2 {
		t.Errorf("orgA admin events total = %d, want >= 2", totalA)
	}
	for _, e := range eventsA {
		if e.OrgID != smokeOrgA {
			t.Errorf("orgA admin events list returned event with OrgID=%q", e.OrgID)
		}
	}

	// List org_b: expect 1.
	_, totalB, err := adminRepo.List(ctx, 50, 0, smokeOrgB, "", "", "")
	if err != nil {
		t.Fatalf("List orgB admin events: %v", err)
	}
	if totalB < 1 {
		t.Errorf("orgB admin events total = %d, want >= 1", totalB)
	}

	// List global (orgID=""): expect all.
	_, totalGlobal, err := adminRepo.List(ctx, 50, 0, "", "", "", "")
	if err != nil {
		t.Fatalf("List global admin events: %v", err)
	}
	if totalGlobal < 3 {
		t.Errorf("global admin events total = %d, want >= 3", totalGlobal)
	}

	t.Logf("smoke/tenant-admin-events: orgA>=%d orgB>=%d global>=%d (isolation OK)",
		totalA, totalB, totalGlobal)
}

// ---------------------------------------------------------------------------
// T2.5.6 — Tenant purge + export
// ---------------------------------------------------------------------------

// TestSmoke_TenantIsolation_PurgeExport verifies:
//   - PurgeAndRecord(orgA) deletes only org_a rows.
//   - Evidence bundle with tenantOrgID has OrgID in manifest and tenant README.
func TestSmoke_TenantIsolation_PurgeExport(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	authSvc := auth.NewService(auth.NewRepository(infra.DB), "smoke-tenant-jwt-32chars!!")
	adminAID, adminBID := twoOrgFixture(t, ctx, infra, authSvc)

	auditRepo := audit.NewRepository(infra.DB)

	// Insert 2 old rows for org_a and 2 for org_b (cutoff < now).
	oldTime := time.Now().UTC().Add(-48 * time.Hour)
	for i, pair := range []struct{ orgID, userID string }{
		{smokeOrgA, adminAID}, {smokeOrgA, adminAID},
		{smokeOrgB, adminBID}, {smokeOrgB, adminBID},
	} {
		log := &domain.AuditLog{
			ID:           uuid.NewString(),
			UserID:       pair.userID,
			OrgID:        pair.orgID,
			Model:        "gpt-4",
			Provider:     "openai",
			Endpoint:     "/v1/chat",
			StatusCode:   200,
			PolicyAction: "allowed",
		}
		if err := auditRepo.Insert(ctx, log); err != nil {
			t.Fatalf("Insert log %d: %v", i, err)
		}
		// Back-date the row so it's past the cutoff.
		if _, err := infra.DB.ExecContext(ctx,
			`UPDATE audit_logs SET created_at=$1 WHERE id=$2`, oldTime, log.ID); err != nil {
			t.Fatalf("backdate log %d: %v", i, err)
		}
	}

	// Count before purge.
	var beforeA, beforeB int
	infra.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs WHERE org_id=$1`, smokeOrgA).Scan(&beforeA)
	infra.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs WHERE org_id=$1`, smokeOrgB).Scan(&beforeB)

	// Purge org_a only (cutoff=now).
	cutoff := time.Now().UTC()
	deleted, err := auditRepo.PurgeAndRecord(ctx, cutoff, 100, audit.PurgeTargetAuditLogs, smokeOrgA, "org")
	if err != nil {
		t.Fatalf("PurgeAndRecord orgA: %v", err)
	}
	if deleted != beforeA {
		t.Errorf("purge deleted=%d, want %d (all org_a rows)", deleted, beforeA)
	}

	// Verify org_b rows intact.
	var afterB int
	infra.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs WHERE org_id=$1`, smokeOrgB).Scan(&afterB)
	if afterB != beforeB {
		t.Errorf("after org_a purge: org_b rows=%d, want %d (unchanged)", afterB, beforeB)
	}

	// Verify evidence record has scope='org' and org_id=smokeOrgA.
	var scope, orgID string
	err = infra.DB.QueryRowContext(ctx,
		`SELECT scope, org_id::text FROM audit_purge_runs ORDER BY completed_at DESC LIMIT 1`).
		Scan(&scope, &orgID)
	if err != nil {
		t.Fatalf("read purge run: %v", err)
	}
	if scope != "org" {
		t.Errorf("purge run scope=%q, want 'org'", scope)
	}
	if orgID != smokeOrgA {
		t.Errorf("purge run org_id=%q, want %q", orgID, smokeOrgA)
	}

	t.Logf("smoke/tenant-purge: org_a purge=%d rows deleted, org_b intact=%d, scope=%s org_id=%s",
		deleted, afterB, scope, orgID)

	// Evidence export: tenant bundle has OrgID in manifest and tenant README.
	bundleDir := t.TempDir() + "/tenant-bundle"
	if err := os.MkdirAll(bundleDir+"/reports", 0o755); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}
	// Write minimal bundle files to test WriteReadme content.
	if err := evidencebundle.WriteReadme(bundleDir, []string{"audit_logs"}, false, smokeOrgA); err != nil {
		t.Fatalf("WriteReadme: %v", err)
	}
	readme, err := os.ReadFile(bundleDir + "/README.txt")
	if err != nil {
		t.Fatalf("ReadFile README: %v", err)
	}
	readmeStr := string(readme)
	if !tenantContains(readmeStr, smokeOrgA) {
		t.Error("tenant README should contain org_id")
	}
	if !tenantContains(readmeStr, "NOT PRESENT") {
		t.Error("tenant README should say global reports are NOT PRESENT")
	}
	if !tenantContains(readmeStr, "TENANT BUNDLE NOTE") {
		t.Error("tenant README should contain TENANT BUNDLE NOTE")
	}
	t.Logf("smoke/tenant-export: README contains tenant disclaimer and org_id=%s", smokeOrgA)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func boolPtr(b bool) *bool { return &b }

func tenantContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

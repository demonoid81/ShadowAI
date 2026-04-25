//go:build enterprise && smoke

// PR-T2.6: Global admin and org management smoke scenarios.
package smoke

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/orgadmin"
)

// ---------------------------------------------------------------------------
// T2.6.1 — RequireGlobalAdmin middleware
// ---------------------------------------------------------------------------

func TestSmoke_GlobalAdmin_Middleware(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	authSvc := auth.NewService(auth.NewRepository(infra.DB), "smoke-global-admin-32chars!!")
	twoOrgFixture(t, ctx, infra, authSvc)

	// Register a global_admin user directly via SQL (cannot use Register — role rejected).
	globalAdminID := "aa000000-0000-4000-8000-000000000001"
	_, err := infra.DB.ExecContext(ctx, `
		INSERT INTO users (id, email, password, role, is_active, token_version, org_id)
		VALUES ($1, 'global@smoke.test', 'x', 'global_admin', true, 0, $2)
		ON CONFLICT (id) DO NOTHING`,
		globalAdminID, domain.DefaultOrgID)
	if err != nil {
		t.Fatalf("insert global_admin: %v", err)
	}

	// Issue JWT for global_admin — use GenerateTokenForUserID.
	globalToken, err := authSvc.GenerateTokenForUserID(ctx, globalAdminID)
	if err != nil {
		t.Fatalf("GenerateToken global_admin: %v", err)
	}
	globalClaims, err := authSvc.ValidateToken(globalToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if globalClaims.Role != auth.RoleGlobalAdmin {
		t.Errorf("global_admin JWT role = %q, want global_admin", globalClaims.Role)
	}
	t.Logf("smoke/global-admin: global_admin JWT issued, role=%s", globalClaims.Role)

	// RequireGlobalAdmin middleware: global_admin → 200.
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	protected := auth.RequireGlobalAdmin(ok)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req = req.WithContext(auth.WithClaims(req.Context(), globalClaims))
	protected.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("global_admin should pass RequireGlobalAdmin, got %d", rr.Code)
	}

	// Regular admin → 403.
	authRepo := auth.NewRepository(infra.DB)
	adminUser, _ := authSvc.Register(ctx, "admin-t26@smoke.test", "StrongPassword123!", auth.RoleAdmin)
	adminToken, _ := authSvc.GenerateTokenForUserID(ctx, adminUser.ID)
	adminClaims, _ := authSvc.ValidateToken(adminToken)
	_ = authRepo

	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2 = req2.WithContext(auth.WithClaims(req2.Context(), adminClaims))
	protected.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Errorf("regular admin should get 403 from RequireGlobalAdmin, got %d", rr2.Code)
	}

	t.Logf("smoke/global-admin: middleware isolation verified (global_admin=200, admin=403)")
}

// ---------------------------------------------------------------------------
// T2.6.2 — Org management API
// ---------------------------------------------------------------------------

func TestSmoke_GlobalAdmin_OrgAPI(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	authSvc := auth.NewService(auth.NewRepository(infra.DB), "smoke-global-admin-32chars!!")
	twoOrgFixture(t, ctx, infra, authSvc)

	// Create global_admin user.
	globalAdminID := "aa000001-0000-4000-8000-000000000001"
	if _, err := infra.DB.ExecContext(ctx,
		`INSERT INTO users (id, email, password, role, is_active, token_version, org_id)
		 VALUES ($1, 'global2@smoke.test', 'x', 'global_admin', true, 0, $2) ON CONFLICT (id) DO NOTHING`,
		globalAdminID, domain.DefaultOrgID); err != nil {
		t.Fatalf("insert global_admin: %v", err)
	}
	globalToken, _ := authSvc.GenerateTokenForUserID(ctx, globalAdminID)
	globalClaims, _ := authSvc.ValidateToken(globalToken)

	adminAuditSvc := adminaudit.NewService(adminaudit.NewRepository(infra.DB))
	repo := orgadmin.NewRepository(infra.DB)
	handler := orgadmin.NewHandler(repo, adminAuditSvc)

	r := mux.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(auth.WithClaims(req.Context(), globalClaims)))
		})
	})
	r.HandleFunc("/api/orgs", handler.ListOrgs).Methods("GET")
	r.HandleFunc("/api/orgs", handler.CreateOrg).Methods("POST")
	r.HandleFunc("/api/orgs/{org_id}", handler.GetOrg).Methods("GET")
	r.HandleFunc("/api/orgs/{org_id}", handler.UpdateOrg).Methods("PATCH")

	// List orgs — should include default + org_a + org_b.
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest("GET", "/api/orgs", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/orgs = %d, want 200", rr.Code)
	}
	var orgs []domain.Organization
	json.NewDecoder(rr.Body).Decode(&orgs)
	if len(orgs) < 3 {
		t.Errorf("expected >= 3 orgs, got %d", len(orgs))
	}
	t.Logf("smoke/global-admin: ListOrgs returned %d orgs", len(orgs))

	// Create new org.
	body := `{"name":"Test Corp","slug":"test-corp-smoke"}`
	rr2 := httptest.NewRecorder()
	r.ServeHTTP(rr2, httptest.NewRequest("POST", "/api/orgs", strings.NewReader(body)))
	if rr2.Code != http.StatusCreated {
		t.Fatalf("POST /api/orgs = %d body=%s, want 201", rr2.Code, rr2.Body.String())
	}
	var created domain.Organization
	json.NewDecoder(rr2.Body).Decode(&created)
	if created.ID == "" || created.Slug != "test-corp-smoke" {
		t.Errorf("created org = %+v", created)
	}
	t.Logf("smoke/global-admin: CreateOrg → id=%s slug=%s", created.ID, created.Slug)

	// Tenant admin cannot list all orgs (RequireGlobalAdmin blocks).
	adminUser, _ := authSvc.Register(ctx, "admin-org-t26@smoke.test", "StrongPassword123!", auth.RoleAdmin)
	adminToken, _ := authSvc.GenerateTokenForUserID(ctx, adminUser.ID)
	adminClaims, _ := authSvc.ValidateToken(adminToken)

	rGlobal := mux.NewRouter()
	rGlobal.Use(auth.RequireGlobalAdmin)
	rGlobal.HandleFunc("/api/orgs", handler.ListOrgs).Methods("GET")

	rr3 := httptest.NewRecorder()
	req3 := httptest.NewRequest("GET", "/api/orgs", nil)
	req3 = req3.WithContext(auth.WithClaims(req3.Context(), adminClaims))
	rGlobal.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusForbidden {
		t.Errorf("tenant admin ListOrgs should be 403, got %d", rr3.Code)
	}
	t.Logf("smoke/global-admin: tenant admin blocked from ListOrgs (403)")
}

// ---------------------------------------------------------------------------
// T2.6.3 — SCIM token management
// ---------------------------------------------------------------------------

func TestSmoke_GlobalAdmin_SCIMTokens(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	authSvc := auth.NewService(auth.NewRepository(infra.DB), "smoke-global-admin-32chars!!")
	twoOrgFixture(t, ctx, infra, authSvc)

	globalAdminID := "aa000002-0000-4000-8000-000000000001"
	if _, err := infra.DB.ExecContext(ctx,
		`INSERT INTO users (id, email, password, role, is_active, token_version, org_id)
		 VALUES ($1, 'global3@smoke.test', 'x', 'global_admin', true, 0, $2) ON CONFLICT (id) DO NOTHING`,
		globalAdminID, domain.DefaultOrgID); err != nil {
		t.Fatalf("insert global_admin: %v", err)
	}
	globalToken, _ := authSvc.GenerateTokenForUserID(ctx, globalAdminID)
	globalClaims, _ := authSvc.ValidateToken(globalToken)

	adminAuditSvc := adminaudit.NewService(adminaudit.NewRepository(infra.DB))
	repo := orgadmin.NewRepository(infra.DB)
	handler := orgadmin.NewHandler(repo, adminAuditSvc)

	r := mux.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(auth.WithClaims(req.Context(), globalClaims)))
		})
	})
	r.HandleFunc("/api/orgs/{org_id}/scim-tokens", handler.ListSCIMTokens).Methods("GET")
	r.HandleFunc("/api/orgs/{org_id}/scim-tokens", handler.CreateSCIMToken).Methods("POST")
	r.HandleFunc("/api/orgs/{org_id}/scim-tokens/{token_id}", handler.RevokeSCIMToken).Methods("DELETE")

	// Create SCIM token for org_a.
	body := `{"label":"smoke-idp"}`
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest("POST", "/api/orgs/"+smokeOrgA+"/scim-tokens", strings.NewReader(body)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST scim-tokens = %d: %s", rr.Code, rr.Body.String())
	}
	var createResp struct {
		Token struct {
			ID    string `json:"id"`
			OrgID string `json:"org_id"`
		} `json:"token"`
		PlainToken string `json:"plain_token"`
		Warning    string `json:"warning"`
	}
	json.NewDecoder(rr.Body).Decode(&createResp)
	if createResp.PlainToken == "" {
		t.Error("plain_token must be returned on create")
	}
	if createResp.Token.OrgID != smokeOrgA {
		t.Errorf("scim token org_id = %q, want %q", createResp.Token.OrgID, smokeOrgA)
	}
	if createResp.Warning == "" {
		t.Error("warning field should be present")
	}
	t.Logf("smoke/global-admin: SCIM token created id=%s org=%s plain_len=%d",
		createResp.Token.ID, createResp.Token.OrgID, len(createResp.PlainToken))

	// Verify token resolves to org_a via scim_tokens table.
	import_sha256 := sha256hex(createResp.PlainToken)
	var resolvedOrg string
	infra.DB.QueryRowContext(ctx,
		`SELECT org_id::text FROM scim_tokens WHERE token_hash = $1 AND is_active = true`,
		import_sha256).Scan(&resolvedOrg)
	if resolvedOrg != smokeOrgA {
		t.Errorf("token resolves to org=%q, want %q", resolvedOrg, smokeOrgA)
	}
	t.Logf("smoke/global-admin: token resolves to org_a ✓")

	// List tokens for org_a.
	rr2 := httptest.NewRecorder()
	r.ServeHTTP(rr2, httptest.NewRequest("GET", "/api/orgs/"+smokeOrgA+"/scim-tokens", nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("GET scim-tokens = %d", rr2.Code)
	}
	var tokens []domain.SCIMToken
	json.NewDecoder(rr2.Body).Decode(&tokens)
	if len(tokens) < 1 {
		t.Errorf("expected >= 1 token for org_a, got %d", len(tokens))
	}

	// Revoke token.
	rr3 := httptest.NewRecorder()
	r.ServeHTTP(rr3, httptest.NewRequest("DELETE",
		"/api/orgs/"+smokeOrgA+"/scim-tokens/"+createResp.Token.ID, nil))
	if rr3.Code != http.StatusNoContent {
		t.Errorf("DELETE scim-token = %d, want 204", rr3.Code)
	}

	// Verify token no longer resolves.
	var activeOrg string
	infra.DB.QueryRowContext(ctx,
		`SELECT org_id::text FROM scim_tokens WHERE token_hash = $1 AND is_active = true`,
		import_sha256).Scan(&activeOrg)
	if activeOrg != "" {
		t.Error("revoked token should not resolve to any org")
	}
	t.Logf("smoke/global-admin: SCIM token revoked, no longer resolves ✓")
}

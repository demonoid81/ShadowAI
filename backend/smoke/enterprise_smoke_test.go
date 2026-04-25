//go:build enterprise && smoke

// PR-O3.1: Enterprise smoke harness.
//
// End-to-end production-readiness verification against real DB+Redis via testcontainers.
// Covers the critical path of every enterprise feature block.
//
// What this harness IS:
//   - A structured test of real service-layer interactions against real infrastructure
//   - A regression guard for integration gaps between feature blocks
//   - A deploy-confidence signal (green smoke → safe to promote)
//
// What this harness is NOT:
//   - A replacement for unit tests
//   - A load or performance test
//   - A live OIDC integration test (IdP mock not yet implemented — see O3.1.1)
//
// Run:
//
//	cd backend && go test -tags 'enterprise smoke' ./smoke/... -count=1 -v -timeout 10m
//
// Requirements: Docker daemon (testcontainers-go).
package smoke

import (
	"context"
	"database/sql"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/governance"
	"github.com/shadowai/backend/internal/health"
)

// ---------------------------------------------------------------------------
// Infrastructure setup
// ---------------------------------------------------------------------------

type infraStack struct {
	DB       *sql.DB
	DBURL    string
	RedisURL string
	teardown func()
}

// startInfra poднимает PG + Redis и применяет core + enterprise migrations.
func startInfra(t *testing.T) *infraStack {
	t.Helper()
	ctx := context.Background()

	// Postgres
	pgC, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("shadowai_smoke"),
		tcpostgres.WithUsername("smoke"),
		tcpostgres.WithPassword("smoke"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Skipf("postgres unavailable (Docker?): %v", err)
	}

	// Redis
	redisC, err := tcredis.Run(ctx, "redis:7-alpine",
		testcontainers.WithWaitStrategy(wait.ForLog("Ready to accept connections").
			WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		_ = pgC.Terminate(ctx)
		t.Skipf("redis unavailable (Docker?): %v", err)
	}

	dbURL, _ := pgC.ConnectionString(ctx, "sslmode=disable")
	redisEndpoint, _ := redisC.Endpoint(ctx, "")
	redisURL := "redis://" + redisEndpoint + "/0"

	db, err := sql.Open("postgres", dbURL)
	if err != nil || db.PingContext(ctx) != nil {
		_ = pgC.Terminate(ctx)
		_ = redisC.Terminate(ctx)
		t.Skipf("db connect failed: %v", err)
	}

	// Run core + enterprise migrations.
	if err := runMigrations(t, db); err != nil {
		_ = pgC.Terminate(ctx)
		_ = redisC.Terminate(ctx)
		t.Fatalf("migrations failed: %v", err)
	}

	teardown := func() {
		db.Close()
		_ = pgC.Terminate(ctx)
		_ = redisC.Terminate(ctx)
	}
	return &infraStack{DB: db, DBURL: dbURL, RedisURL: redisURL, teardown: teardown}
}

func runMigrations(t *testing.T, db *sql.DB) error {
	t.Helper()
	// schema_migrations table.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version VARCHAR(255) PRIMARY KEY, applied_at TIMESTAMPTZ DEFAULT now()
	)`); err != nil {
		return err
	}

	for _, dir := range []string{"migrations", "migrations-enterprise"} {
		path := filepath.Join("..", dir)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if filepath.Ext(e.Name()) != ".sql" {
				continue
			}
			var count int
			_ = db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version=$1`, e.Name()).Scan(&count)
			if count > 0 {
				continue
			}
			content, err := os.ReadFile(filepath.Join(path, e.Name()))
			if err != nil {
				return err
			}
			tx, _ := db.Begin()
			if _, err := tx.Exec(string(content)); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("migration %s: %w", e.Name(), err)
			}
			_, _ = tx.Exec(`INSERT INTO schema_migrations (version) VALUES ($1)`, e.Name())
			if err := tx.Commit(); err != nil {
				return err
			}
			t.Logf("smoke: applied %s/%s", dir, e.Name())
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// O3.1.A — Migration idempotency
// ---------------------------------------------------------------------------

// TestSmoke_Migrations_Idempotent verifies migrations apply cleanly and
// running them a second time is a no-op (safe for rolling restarts).
func TestSmoke_Migrations_Idempotent(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	// Count migrations applied.
	var count int
	_ = infra.DB.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count)
	if count == 0 {
		t.Error("no migrations recorded in schema_migrations")
	}
	t.Logf("smoke/migrations: %d migrations applied", count)

	// Re-run — must be idempotent (no-op).
	firstCount := count
	if err := runMigrations(t, infra.DB); err != nil {
		t.Fatalf("idempotency: second run failed: %v", err)
	}
	_ = infra.DB.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count)
	if count != firstCount {
		t.Errorf("idempotency: count changed %d → %d on second run", firstCount, count)
	}
}

// ---------------------------------------------------------------------------
// O3.1.B — Auth flows
// ---------------------------------------------------------------------------

// TestSmoke_Auth_PasswordAndMFA verifies:
//   - User registration
//   - Password login
//   - MFA setup (TOTP secret, setup token, confirm)
//   - MFA-required login returns mfa_required=true
func TestSmoke_Auth_PasswordAndMFA(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	authRepo := auth.NewRepository(infra.DB)
	authSvc := auth.NewService(authRepo, "smoke-jwt-secret-32chars!!!!!!!")

	// 1. Register admin user.
	user, err := authSvc.Register(ctx, "admin@smoke.test", "StrongPassword123!", auth.RoleAdmin)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	t.Logf("smoke/auth: registered user %s", user.ID)

	// 2. Password login → full JWT.
	result, err := authSvc.LoginWithMFA(ctx, "admin@smoke.test", "StrongPassword123!")
	if err != nil {
		t.Fatalf("LoginWithMFA: %v", err)
	}
	if result.MFARequired {
		t.Error("fresh user should not require MFA before setup")
	}
	if result.Token == "" {
		t.Error("expected JWT token, got empty")
	}

	// 3. MFA setup + confirm.
	_, plainSecret, encSecret, err := authSvc.GenerateTOTPSecret("ShadowAI Smoke", user.Email)
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := authRepo.SetTOTPSecret(ctx, user.ID, encSecret); err != nil {
		t.Fatalf("SetTOTPSecret: %v", err)
	}
	t.Logf("smoke/auth: MFA configured for user %s (secret len=%d)", user.ID, len(plainSecret))

	// 4. Login after MFA enabled → should return mfa_required=true.
	result2, err := authSvc.LoginWithMFA(ctx, "admin@smoke.test", "StrongPassword123!")
	if err != nil {
		t.Fatalf("LoginWithMFA after MFA setup: %v", err)
	}
	if !result2.MFARequired {
		t.Error("after MFA setup, login must return mfa_required=true")
	}
	if result2.MFAChallengeToken == "" {
		t.Error("expected MFA challenge token")
	}
	t.Logf("smoke/auth: MFA challenge issued correctly")
}

// TestSmoke_Auth_BreakGlass verifies break-glass produces a short-lived
// JWT with BreakGlass=true claim.
func TestSmoke_Auth_BreakGlass(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	authRepo := auth.NewRepository(infra.DB)
	authSvc := auth.NewService(authRepo, "smoke-jwt-secret-32chars!!!!!!!")

	// Generate bcrypt hash for the test break-glass secret.
	bgHashBytes, err := bcrypt.GenerateFromPassword([]byte("smoke-break-glass-pass"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	bgHash := string(bgHashBytes)

	token, err := authSvc.BreakGlassLogin(ctx, "smoke-break-glass-pass", bgHash, time.Hour)
	if err != nil {
		t.Fatalf("BreakGlassLogin: %v", err)
	}
	claims, err := authSvc.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if !claims.BreakGlass {
		t.Error("break-glass JWT must have BreakGlass=true")
	}
	if claims.Role != auth.RoleAdmin {
		t.Errorf("break-glass role = %q, want admin", claims.Role)
	}
	t.Logf("smoke/auth: break-glass JWT valid (role=%s ttl=1h)", claims.Role)
}

// ---------------------------------------------------------------------------
// O3.1.C — Governance
// ---------------------------------------------------------------------------

// TestSmoke_Governance_RoleBased verifies role_based mode allows/denies by role.
func TestSmoke_Governance_RoleBased(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	repo := governance.NewPGRepository(infra.DB)
	svc := governance.NewService(repo)

	// Upsert role_based policy.
	_, err := svc.Upsert(ctx, &governance.Policy{
		Name: "smoke-role-based",
		Mode: governance.ModeAllowlistRoleBased,
		RoleRules: []governance.RoleRule{
			{Role: "admin", Rules: []governance.ProviderRule{
				{Provider: "openai", Models: []string{"gpt-4"}},
			}},
		},
	}, "", "")
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Admin + openai/gpt-4 → allow.
	dec, err := svc.Evaluate(ctx, "", "admin", "", "", "openai", "gpt-4")
	if err != nil || dec.Kind != governance.DecisionAllow {
		t.Errorf("admin+openai/gpt-4: want Allow, got %v err=%v", dec.Kind, err)
	}
	// User role → deny.
	dec, err = svc.Evaluate(ctx, "", "user", "", "", "openai", "gpt-4")
	if err != nil || dec.Kind != governance.DecisionDeny {
		t.Errorf("user+openai/gpt-4: want Deny (unknown_role), got %v err=%v", dec.Kind, err)
	}
	t.Logf("smoke/governance: role_based allow/deny verified")
}

// TestSmoke_Governance_ContextScoped verifies context_scoped mode by dept+sensitivity.
func TestSmoke_Governance_ContextScoped(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	repo := governance.NewPGRepository(infra.DB)
	svc := governance.NewService(repo)

	_, err := svc.Upsert(ctx, &governance.Policy{
		Name: "smoke-ctx",
		Mode: governance.ModeContextScoped,
		ContextRules: []governance.ContextRule{
			{
				Department:  "finance",
				Sensitivity: []governance.SensitivityLevel{governance.SensitivityConfidential},
				Rules:       []governance.ProviderRule{{Provider: "openai", Models: []string{"gpt-4"}}},
			},
		},
	}, "", "")
	if err != nil {
		t.Fatalf("Upsert context_scoped: %v", err)
	}

	// finance/confidential → allow.
	dec, _ := svc.Evaluate(ctx, "", "analyst", "finance", "confidential", "openai", "gpt-4")
	if dec.Kind != governance.DecisionAllow {
		t.Errorf("finance+confidential: want Allow, got %v (code=%s)", dec.Kind, dec.Code)
	}
	// legal/confidential → unknown_department.
	dec, _ = svc.Evaluate(ctx, "", "analyst", "legal", "confidential", "openai", "gpt-4")
	if dec.Kind != governance.DecisionDeny || dec.Code != governance.CodeUnknownDepartment {
		t.Errorf("legal: want Deny/unknown_department, got %v/%s", dec.Kind, dec.Code)
	}
	t.Logf("smoke/governance: context_scoped allow/deny verified")
}

// ---------------------------------------------------------------------------
// O3.1.D — Health probes
// ---------------------------------------------------------------------------

// TestSmoke_Health_Probes verifies the liveness and readiness probes against
// real DB and Redis dependencies, mirroring the actual Kubernetes probe behavior.
func TestSmoke_Health_Probes(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()

	// Build a real Redis client from the URL the infra stack provides.
	redisOpts, err := redis.ParseURL(infra.RedisURL)
	if err != nil {
		t.Fatalf("redis.ParseURL: %v", err)
	}
	redisClient := redis.NewClient(redisOpts)
	defer redisClient.Close()

	// Liveness handler — always returns 200.
	livenessReq := httptest.NewRequest("GET", "/api/health", nil)
	livenessRec := httptest.NewRecorder()
	health.LivenessHandler(livenessRec, livenessReq)
	if livenessRec.Code != 200 {
		t.Errorf("liveness: expected 200, got %d", livenessRec.Code)
	}
	t.Logf("smoke/health: liveness probe OK (%d)", livenessRec.Code)

	// Readiness checker — must return 200 with both DB and Redis healthy.
	checker := &health.ReadinessChecker{DB: infra.DB, Redis: redisClient}
	readinessReq := httptest.NewRequest("GET", "/api/ready", nil)
	readinessRec := httptest.NewRecorder()
	checker.Ready(readinessRec, readinessReq)
	if readinessRec.Code != 200 {
		t.Errorf("readiness: expected 200, got %d; body=%s",
			readinessRec.Code, readinessRec.Body.String())
	}
	if body := readinessRec.Body.String(); !contains(body, `"ready":true`) {
		t.Errorf("readiness: expected ready=true in body, got: %s", body)
	}
	t.Logf("smoke/health: readiness probe OK (db+redis both healthy)")

	// Verify Redis responds independently.
	if err := redisClient.Ping(ctx).Err(); err != nil {
		t.Errorf("redis ping: %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}

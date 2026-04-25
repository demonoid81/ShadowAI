//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// Compiled only under -tags enterprise.

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/config"
	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/governance"
	"github.com/shadowai/backend/internal/legalhold"
	"github.com/shadowai/backend/internal/oidcauth"
	"github.com/shadowai/backend/internal/scim"
	"github.com/shadowai/backend/internal/siem"
)

// buildEnterpriseBundle (Enterprise-build) создаёт full-featured
// bundle: admin_event_logs repo/service/handler, DSAR erasure
// service, Provider/Model Governance service/handler; регистрирует
// admin-only enterprise routes и retention-schedulers.
func buildEnterpriseBundle(deps enterpriseDeps) *enterpriseBundle {
	// Admin audit (PR-D).
	adminAuditRepo := adminaudit.NewRepository(deps.DB).WithChainSecret(deps.Cfg.AuditChainSecret)
	adminAuditSvc := adminaudit.NewService(adminAuditRepo)
	adminAuditHandler := adminaudit.NewHandler(adminAuditRepo)

	// PR-S1.1: SIEM mirror with async queue + batch delivery.
	// Primary flow: handlers write through adminAuditRecorder → DB + SIEM fanout.
	// SIEM side is fully async: Record() enqueues without blocking the request path.
	// Worker goroutine is started later in StartSchedulers (ctx available there).
	var adminAuditRecorder adminaudit.Recorder = adminAuditSvc
	var siemAsync *siem.AsyncBatchRecorder
	if deps.Cfg.SIEMEnabled && deps.Cfg.SIEMEndpoint != "" {
		httpRec := siem.NewHTTPRecorder(
			deps.Cfg.SIEMEndpoint,
			deps.Cfg.SIEMBearerToken,
			deps.Cfg.SIEMTimeout,
			deps.Cfg.SIEMInsecureSkipVerify,
		)
		dropPolicy, err := siem.ParseDropPolicy(deps.Cfg.SIEMDropPolicy)
		if err != nil {
			log.Fatalf("siem: invalid SIEM_DROP_POLICY: %v", err)
		}
		siemAsync = siem.NewAsyncBatchRecorder(httpRec, siem.AsyncBatchOptions{
			QueueSize:     deps.Cfg.SIEMQueueSize,
			BatchSize:     deps.Cfg.SIEMBatchSize,
			FlushInterval: deps.Cfg.SIEMFlushInterval,
			MaxRetries:    deps.Cfg.SIEMMaxRetries,
			DropPolicy:    dropPolicy,
		})
		adminAuditRecorder = &siem.FanoutAdminRecorder{
			DB:   adminAuditSvc,
			SIEM: siemAsync,
		}
		log.Printf("siem: async batch recorder configured (queue=%d batch=%d flush=%s retries=%d policy=%s)",
			deps.Cfg.SIEMQueueSize, deps.Cfg.SIEMBatchSize, deps.Cfg.SIEMFlushInterval,
			deps.Cfg.SIEMMaxRetries, deps.Cfg.SIEMDropPolicy)
	}

	// PR-L1: Legal hold (migration 013). Wired до erasureSvc чтобы
	// сразу передать HoldChecker.
	legalHoldRepo := legalhold.NewPGRepository(deps.DB).WithChainSecret(deps.Cfg.AuditChainSecret)
	legalHoldSvc := legalhold.NewService(legalHoldRepo)
	// PR-L1.2: keyed HMAC tokenizer для case_ref. Prod startup-guard
	// (ValidateStartupConfig) уже гарантирует, что LegalHoldTokenSecret
	// задан и >=32 chars. Dev: пустой secret → unkeyed fallback с
	// warning.
	legalHoldHandler := legalhold.NewHandlerWithSecret(
		legalHoldSvc, adminAuditRecorder, deps.Cfg.LegalHoldTokenSecret,
	)

	// DSAR erasure (PR-B). auditRepo + budgetRepo используются как
	// AuditScrubber + BudgetDeleter через interface intersection.
	// PR-L1: HoldChecker attached через chainable setter — erasure
	// pre-tx проверяет hold и возвращает ErasureHoldActive.
	erasureSvc := auth.NewErasureService(deps.DB, deps.AuditRepo, deps.BudgetRepo).
		WithHoldChecker(legalHoldSvc)

	// Provider/Model Governance (PR-G1). Singleton via migration 012.
	governanceRepo := governance.NewPGRepository(deps.DB)
	governanceSvc := governance.NewService(governanceRepo)
	governanceHandler := governance.NewHandler(governanceSvc, adminAuditRecorder)

	// PR-E2: SCIM provisioning.
	var scimHandler *scim.Handler
	if deps.Cfg.SCIMEnabled {
		scimCfg, err := scim.ParseSyncConfig(
			deps.Cfg.SCIMProvisionDefaultRole,
			deps.Cfg.SCIMRoleMapJSON,
			deps.Cfg.SCIMDepartmentAttribute,
			deps.Cfg.SCIMLinkByEmail,
		)
		if err != nil {
			log.Fatalf("scim: config error: %v", err)
		}
		syncer := scim.NewUserSyncer(deps.AuthRepo, scimCfg)
		scimBaseURL := deps.Cfg.OIDCRedirectURL // reuse base URL from OIDC config as hint
		if idx := strings.Index(scimBaseURL, "/api/"); idx > 0 {
			scimBaseURL = scimBaseURL[:idx]
		}
		scimBaseURL += "/scim/v2"
		baseHandler := scim.NewHandler(syncer, deps.Cfg.SCIMBearerToken, scimBaseURL, adminAuditRecorder)
		// PR-T2.3.2: per-request token → org resolution via scim_tokens table.
		tokenRepo := scim.NewSCIMTokensRepository(deps.DB)
		baseHandler = baseHandler.WithTokenResolver(tokenRepo)
		// Also resolve the static bearer token for the legacy single-token path.
		scimOrgID := resolveSCIMTokenOrg(context.Background(), deps.DB, deps.Cfg.SCIMBearerToken)
		scimHandler = baseHandler.WithOrgID(scimOrgID)
		log.Printf("scim: provisioning enabled (default_role=%s link_by_email=%v org=%s)",
			scimCfg.DefaultRole, scimCfg.LinkByEmail, scimOrgID)
	}

	// PR-E1.1: MFA + break-glass handler.
	mfaCfg := auth.MFAConfig{
		MFATOTPIssuer:        deps.Cfg.MFATOTPIssuer,
		BreakGlassEnabled:    deps.Cfg.BreakGlassEnabled,
		BreakGlassSecretHash: deps.Cfg.BreakGlassSecretHash,
		BreakGlassJWTTTL:     deps.Cfg.BreakGlassJWTTTL,
	}
	mfaHandler := auth.NewMFAHandler(deps.AuthSvc, mfaCfg, adminAuditRecorder)

	// PR-E1: OIDC enterprise auth.
	// Handler is created at wire time; actual HTTP server context not yet available,
	// so provider discovery is deferred to RegisterPublicRoutes (called after server start).
	oidcCfg, oidcCfgErr := oidcauth.FromAppConfig(deps.Cfg)
	if oidcCfgErr != nil {
		log.Fatalf("oidc: config error: %v", oidcCfgErr)
	}

	return &enterpriseBundle{
		AdminAudit: adminAuditRecorder,
		Governance: governanceSvc,
		Eraser:     erasureSvc,

		// PR-E2: SCIM 2.0 routes (separate bearer token, not admin JWT).
		RegisterSCIMRoutes: func(r *mux.Router) {
			if scimHandler == nil {
				return // SCIM_ENABLED=false
			}
			scimRouter := r.PathPrefix("/scim/v2").Subrouter()
			scimRouter.Use(scimHandler.BearerAuth)
			scimRouter.HandleFunc("/ServiceProviderConfig", scimHandler.ServiceProviderConfig).Methods("GET")
			scimRouter.HandleFunc("/Users",       scimHandler.ListUsers).Methods("GET")
			scimRouter.HandleFunc("/Users",       scimHandler.CreateUser).Methods("POST")
			scimRouter.HandleFunc("/Users/{id}",  scimHandler.GetUser).Methods("GET")
			scimRouter.HandleFunc("/Users/{id}",  scimHandler.ReplaceUser).Methods("PUT")
			scimRouter.HandleFunc("/Users/{id}",  scimHandler.PatchUser).Methods("PATCH")
			scimRouter.HandleFunc("/Users/{id}",  scimHandler.DeleteUser).Methods("DELETE")
		},

		// PR-E1.1: MFA management routes (behind AuthMiddleware, admin-only).
		RegisterMFARoutes: func(api *mux.Router) {
			mfaAdmin := api.PathPrefix("").Subrouter()
			mfaAdmin.Use(auth.RequireRole(auth.RoleAdmin))
			mfaAdmin.HandleFunc("/auth/mfa/setup",   mfaHandler.MFASetup).Methods("POST")
			mfaAdmin.HandleFunc("/auth/mfa/confirm", mfaHandler.MFAConfirm).Methods("POST")
			mfaAdmin.HandleFunc("/auth/mfa",         mfaHandler.MFADisable).Methods("DELETE")
		},

		// PR-E1: register OIDC public routes.
		RegisterPublicRoutes: func(publicAuth *mux.Router) {
			// Break-glass (public — emergency access without existing JWT).
			if mfaCfg.BreakGlassEnabled || true { // always register route; handler checks config
				publicAuth.HandleFunc("/break-glass", mfaHandler.BreakGlass).Methods("POST")
			}
			// MFA verify (public — user has mfa_token from password-step, not full JWT).
			publicAuth.HandleFunc("/mfa/verify", mfaHandler.MFAVerify).Methods("POST")
			if oidcCfg == nil {
				return // OIDC_ENABLED=false
			}
			syncer := oidcauth.NewUserSyncer(deps.AuthRepo, oidcCfg, deps.AuthSvc)
			secure := !strings.HasPrefix(deps.Cfg.OIDCRedirectURL, "http://localhost")
			discCtx, discCancel := context.WithTimeout(context.Background(), deps.Cfg.OIDCDiscoveryTimeout)
			defer discCancel()
			oidcHandler, err := oidcauth.NewHandler(
				discCtx,
				oidcCfg,
				syncer,
				deps.AuthSvc,
				adminAuditRecorder,
				secure,
			)
			if err != nil {
				log.Fatalf("oidc: provider init: %v", err)
			}
			publicAuth.HandleFunc("/oidc/login", oidcHandler.Login).Methods("GET")
			publicAuth.HandleFunc("/oidc/callback", oidcHandler.Callback).Methods("GET")
			log.Printf("oidc: routes registered (issuer=%s auto_provision=%v link_by_email=%v)",
				oidcCfg.IssuerURL, oidcCfg.AutoProvision, oidcCfg.LinkByEmail)
		},

		RegisterRoutes: func(admin *mux.Router, authHandler *auth.Handler) {
			// PR-B: DSAR erasure. Admin-only, идемпотентный.
			admin.HandleFunc("/users/{id}/erase", authHandler.EraseUser).Methods("POST")
			// PR-D: admin access audit list.
			admin.HandleFunc("/admin-events", adminAuditHandler.List).Methods("GET")
			// PR-G1: Provider/Model Governance CRUD.
			admin.HandleFunc("/governance/policy", governanceHandler.GetPolicy).Methods("GET")
			admin.HandleFunc("/governance/policy", governanceHandler.UpdatePolicy).Methods("PUT")
			// PR-L1: Legal holds (admin-only).
			// PR-L2.3: 4-eyes workflow — create делает pending,
			// approve/reject нужны для transition → active/released.
			admin.HandleFunc("/legal-holds", legalHoldHandler.Create).Methods("POST")
			admin.HandleFunc("/legal-holds", legalHoldHandler.List).Methods("GET")
			admin.HandleFunc("/legal-holds/{id}/approve", legalHoldHandler.Approve).Methods("POST")
			admin.HandleFunc("/legal-holds/{id}/reject", legalHoldHandler.Reject).Methods("POST")
			admin.HandleFunc("/legal-holds/{id}/release", legalHoldHandler.Release).Methods("POST")
		},

		// PR-W3: enterprise tables добавляются к anchor scheduler'у.
		AnchorExtraTables: []string{"admin_event_logs", "legal_hold_events"},

		StartSchedulers: func(ctx context.Context, cfg *config.Config) {
			// PR-S1.1: start SIEM async batch worker.
			// Worker runs until ctx is cancelled; drains queue on shutdown.
			if siemAsync != nil {
				go siemAsync.Run(ctx)
			}

			// PR-A: audit-purge scheduler для audit_logs.
			// PR-S1: purge events тоже уходят в SIEM через fanout recorder.
			// PR-L2: legalHoldSvc передаётся для retention-aware purge —
			// rows под active hold не удаляются даже если они старше
			// cutoff'а.
			if cfg.AuditPurgeInterval > 0 && cfg.AuditRetentionDays > 0 {
				go runAuditPurgeScheduler(ctx, cfg, deps.AuditSvc, adminAuditRecorder, legalHoldSvc)
			}
			// PR-D.1: admin-events purge scheduler.
			if cfg.AuditPurgeInterval > 0 && cfg.AdminAuditRetentionDays > 0 {
				go runAdminEventsPurgeScheduler(ctx, cfg, deps.AuditRepo, adminAuditRepo, adminAuditRecorder)
			}
		},
	}
}

// runAuditPurgeScheduler — PR-A + PR-L2: периодический purge
// audit_logs с retention-aware exclusion. Перед каждым purge tick
// получает список active-hold user_ids; audit rows этих users'ов
// НЕ удаляются даже если созданы раньше cutoff'а. Пишет admin_event
// с excluded_hold_count metadata для forensics.
//
// Fail-closed: если legalhold.ActiveUserIDs fails, purge пропускается
// — compliance (preserve evidence) выше availability (освободить
// диск).
func runAuditPurgeScheduler(ctx context.Context, cfg *config.Config, auditSvc *audit.Service, adminAuditSvc adminaudit.Recorder, legalHoldSvc *legalhold.Service) {
	log.Printf("audit-purge scheduler: interval=%s retention=%d days chunk=%d",
		cfg.AuditPurgeInterval, cfg.AuditRetentionDays, cfg.AuditPurgeChunkSize)
	ticker := time.NewTicker(cfg.AuditPurgeInterval)
	defer ticker.Stop()
	// PR-L3: coordinated purge + record-run в одной tx под
	// advisory lock. Structural interface — decorator-friendly
	// (metrics/tracing wrapper проходит проверку если forward'ит
	// метод). Mismatch → admin-event + SIEM mirror (не silent
	// log). `RecordPurgeRun` больше не вызывается scheduler'ом
	// отдельно — он входит в coordinated method.
	type coordinatedHoldPurger interface {
		PurgeOlderThanRespectingHoldsAndRecordRun(ctx context.Context, cutoff time.Time, chunkSize int) (int, error)
	}
	repoIface := auditSvc.GetRepo()
	repo, ok := repoIface.(coordinatedHoldPurger)
	if !ok {
		log.Printf("audit-purge scheduler: audit.Repo does not implement coordinatedHoldPurger (%T) — scheduler not started", repoIface)
		adminAuditSvc.Record(ctx, adminaudit.Event{
			ActorUserID: nil, Action: "scheduler_init_failed",
			Resource: "audit_logs",
			Path:     "scheduler", Method: "INTERNAL", Success: false,
			Metadata: map[string]any{
				"error_code":    "repo_missing_coordinated_hold_purger",
				"repo_concrete": fmt.Sprintf("%T", repoIface),
				"component":     "runAuditPurgeScheduler",
			},
		})
		return
	}
	purge := func() {
		cutoff := time.Now().UTC().Add(-time.Duration(cfg.AuditRetentionDays) * 24 * time.Hour)
		rctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()

		// PR-L2.1 / PR-L2.2: СУЖАЕТ race-window через single-SQL
		// DELETE с NOT EXISTS(...FROM legal_holds). Под READ COMMITTED
		// statement берёт snapshot в начале DELETE — hold applied
		// ПОСЛЕ начала DELETE ещё не виден, его rows могут удалиться
		// на этом tick'е. На следующем tick'е уже защищены.
		//
		// Истинно race-free design (SERIALIZABLE / advisory lock) —
		// roadmap PR-L3 coordination. Текущая реализация достаточна
		// если AUDIT_PURGE_INTERVAL >> время apply_hold round-trip'а
		// (default values это покрывают).
		//
		// heldUserIDs-snapshot продолжаем брать ТОЛЬКО для
		// metadata.holds_excluded (для forensics UI / SIEM). Race
		// в этом числе acceptable — correctness-impact нет.
		heldUserIDs, err := legalHoldSvc.ActiveUserIDs(rctx)
		if err != nil {
			log.Printf("audit-purge scheduler: hold lookup failed (skip tick): %v", err)
			adminAuditSvc.Record(rctx, adminaudit.Event{
				ActorUserID: nil, Action: "purge", Resource: "audit_logs",
				Path: "scheduler", Method: "INTERNAL", Success: false,
				Metadata: map[string]any{
					"mode": "scheduler", "cutoff": cutoff.Format(time.RFC3339),
					"error": "hold_lookup_failed",
				},
			})
			return
		}

		// PR-L3: coordinated purge + record-run в одной tx под
		// advisory lock. RecordPurgeRun больше не вызывается
		// отдельно — это часть того же atomic method.
		deleted, err := repo.PurgeOlderThanRespectingHoldsAndRecordRun(rctx, cutoff, cfg.AuditPurgeChunkSize)
		if err != nil {
			log.Printf("audit-purge scheduler: err: %v", err)
			adminAuditSvc.Record(rctx, adminaudit.Event{
				ActorUserID: nil, Action: "purge", Resource: "audit_logs",
				Path: "scheduler", Method: "INTERNAL", Success: false,
				Metadata: map[string]any{
					"mode": "scheduler", "cutoff": cutoff.Format(time.RFC3339),
					"error": err.Error(),
				},
			})
			return
		}
		log.Printf("audit-purge scheduler: deleted %d rows (cutoff=%s, holds_excluded=%d)",
			deleted, cutoff.Format(time.RFC3339), len(heldUserIDs))
		adminAuditSvc.Record(rctx, adminaudit.Event{
			ActorUserID: nil, Action: "purge", Resource: "audit_logs",
			Path: "scheduler", Method: "INTERNAL", Success: true,
			Metadata: map[string]any{
				"mode": "scheduler", "cutoff": cutoff.Format(time.RFC3339),
				"rows_deleted":    deleted,
				"holds_excluded":  len(heldUserIDs), // PR-L2
			},
		})
	}
	for {
		select {
		case <-ticker.C:
			purge()
		case <-ctx.Done():
			return
		}
	}
}

// runAdminEventsPurgeScheduler — PR-D.1: периодический purge
// admin_event_logs (обычно отдельный, более длинный retention, чем
// audit_logs — compliance).
func runAdminEventsPurgeScheduler(ctx context.Context, cfg *config.Config, auditRepoHandle audit.Repo, adminAuditRepo *adminaudit.Repository, adminAuditSvc adminaudit.Recorder) {
	log.Printf("admin-events purge scheduler: interval=%s retention=%d days chunk=%d",
		cfg.AuditPurgeInterval, cfg.AdminAuditRetentionDays, cfg.AuditPurgeChunkSize)
	ticker := time.NewTicker(cfg.AuditPurgeInterval)
	defer ticker.Stop()
	purge := func() {
		cutoff := time.Now().UTC().Add(-time.Duration(cfg.AdminAuditRetentionDays) * 24 * time.Hour)
		rctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
		// W2.5: truly atomic PurgeAndRecord — all deletes + evidence INSERT in one tx.
		// RecordPurgeRunTx requires *audit.Repository; misconfig (e.g. wrapper type)
		// is a fatal scheduler error: skip tick, log + admin event, do NOT purge without evidence.
		auditConcreteRepo, ok := auditRepoHandle.(*audit.Repository)
		if !ok {
			log.Printf("admin-events purge scheduler: MISCONFIG — auditRepoHandle is not *audit.Repository; skipping tick to preserve evidence integrity")
			adminAuditSvc.Record(rctx, adminaudit.Event{
				ActorUserID: nil, Action: "purge", Resource: adminaudit.PurgeTarget,
				Path: "scheduler", Method: "INTERNAL", Success: false,
				Metadata: map[string]any{
					"mode": "scheduler", "target": adminaudit.PurgeTarget,
					"error": "audit repo type assertion failed — cannot guarantee atomic evidence; skipping purge tick",
				},
			})
			return
		}
		var deleted int
		var err error
		// Scheduler = system-level global purge; orgID="" = no org filter.
		deleted, err = adminAuditRepo.PurgeAndRecord(rctx, cutoff, cfg.AuditPurgeChunkSize, "", func(c context.Context, tx *sql.Tx, total int) error {
			return auditConcreteRepo.RecordPurgeRunTx(c, tx, cutoff, total, adminaudit.PurgeTarget, "", "global")
		})
		if err != nil {
			log.Printf("admin-events purge scheduler: err: %v", err)
			adminAuditSvc.Record(rctx, adminaudit.Event{
				ActorUserID: nil, Action: "purge", Resource: adminaudit.PurgeTarget,
				Path: "scheduler", Method: "INTERNAL", Success: false,
				Metadata: map[string]any{
					"mode": "scheduler", "target": adminaudit.PurgeTarget,
					"cutoff": cutoff.Format(time.RFC3339), "error": err.Error(),
				},
			})
			return
		}
		log.Printf("admin-events purge scheduler: deleted %d rows (cutoff=%s)", deleted, cutoff.Format(time.RFC3339))
		adminAuditSvc.Record(rctx, adminaudit.Event{
			ActorUserID: nil, Action: "purge", Resource: adminaudit.PurgeTarget,
			Path: "scheduler", Method: "INTERNAL", Success: true,
			Metadata: map[string]any{
				"mode": "scheduler", "target": adminaudit.PurgeTarget,
				"cutoff": cutoff.Format(time.RFC3339), "rows_deleted": deleted,
			},
		})
	}
	for {
		select {
		case <-ticker.C:
			purge()
		case <-ctx.Done():
			return
		}
	}
}

// resolveSCIMTokenOrg looks up org_id in scim_tokens by bearer token hash.
// Returns DefaultOrgID when the token is not registered (single-tenant / legacy path).
func resolveSCIMTokenOrg(ctx context.Context, db *sql.DB, bearerToken string) string {
	if db == nil || bearerToken == "" {
		return domain.DefaultOrgID
	}
	sum := sha256.Sum256([]byte(bearerToken))
	tokenHash := hex.EncodeToString(sum[:])
	var orgID string
	err := db.QueryRowContext(ctx,
		`SELECT org_id FROM scim_tokens WHERE token_hash = $1 AND is_active = true LIMIT 1`,
		tokenHash).Scan(&orgID)
	if err != nil {
		// Token not in scim_tokens (pre-migration / single-tenant): use default org.
		return domain.DefaultOrgID
	}
	return orgID
}

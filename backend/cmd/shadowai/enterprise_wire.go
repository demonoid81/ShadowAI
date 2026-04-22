//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// Compiled only under -tags enterprise.

package main

import (
	"context"
	"log"
	"time"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/config"
	"github.com/shadowai/backend/internal/governance"
	"github.com/shadowai/backend/internal/legalhold"
	"github.com/shadowai/backend/internal/siem"
)

// buildEnterpriseBundle (Enterprise-build) создаёт full-featured
// bundle: admin_event_logs repo/service/handler, DSAR erasure
// service, Provider/Model Governance service/handler; регистрирует
// admin-only enterprise routes и retention-schedulers.
func buildEnterpriseBundle(deps enterpriseDeps) *enterpriseBundle {
	// Admin audit (PR-D).
	adminAuditRepo := adminaudit.NewRepository(deps.DB)
	adminAuditSvc := adminaudit.NewService(adminAuditRepo)
	adminAuditHandler := adminaudit.NewHandler(adminAuditRepo)

	// PR-S1: SIEM mirror. Если SIEM_ENABLED=true и endpoint задан —
	// оборачиваем adminAuditSvc fan-out recorder'ом. Primary flow:
	// handlers писать через adminAuditRecorder, который делает
	// DB+SIEM (fail-open по SIEM).
	var adminAuditRecorder adminaudit.Recorder = adminAuditSvc
	if deps.Cfg.SIEMEnabled && deps.Cfg.SIEMEndpoint != "" {
		siemRec := siem.NewHTTPRecorder(
			deps.Cfg.SIEMEndpoint,
			deps.Cfg.SIEMBearerToken,
			deps.Cfg.SIEMTimeout,
			deps.Cfg.SIEMInsecureSkipVerify,
		)
		adminAuditRecorder = &siem.FanoutAdminRecorder{
			DB:   adminAuditSvc,
			SIEM: siemRec,
		}
	}

	// PR-L1: Legal hold (migration 013). Wired до erasureSvc чтобы
	// сразу передать HoldChecker.
	legalHoldRepo := legalhold.NewPGRepository(deps.DB)
	legalHoldSvc := legalhold.NewService(legalHoldRepo)
	legalHoldHandler := legalhold.NewHandler(legalHoldSvc, adminAuditRecorder)

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

	return &enterpriseBundle{
		AdminAudit: adminAuditRecorder,
		Governance: governanceSvc,
		Eraser:     erasureSvc,

		RegisterRoutes: func(admin *mux.Router, authHandler *auth.Handler) {
			// PR-B: DSAR erasure. Admin-only, идемпотентный.
			admin.HandleFunc("/users/{id}/erase", authHandler.EraseUser).Methods("POST")
			// PR-D: admin access audit list.
			admin.HandleFunc("/admin-events", adminAuditHandler.List).Methods("GET")
			// PR-G1: Provider/Model Governance CRUD.
			admin.HandleFunc("/governance/policy", governanceHandler.GetPolicy).Methods("GET")
			admin.HandleFunc("/governance/policy", governanceHandler.UpdatePolicy).Methods("PUT")
			// PR-L1: Legal holds (admin-only).
			admin.HandleFunc("/legal-holds", legalHoldHandler.Create).Methods("POST")
			admin.HandleFunc("/legal-holds", legalHoldHandler.List).Methods("GET")
			admin.HandleFunc("/legal-holds/{id}/release", legalHoldHandler.Release).Methods("POST")
		},

		StartSchedulers: func(ctx context.Context, cfg *config.Config) {
			// PR-A: audit-purge scheduler для audit_logs.
			// PR-S1: purge events тоже уходят в SIEM через fanout recorder.
			if cfg.AuditPurgeInterval > 0 && cfg.AuditRetentionDays > 0 {
				go runAuditPurgeScheduler(ctx, cfg, deps.AuditSvc, adminAuditRecorder)
			}
			// PR-D.1: admin-events purge scheduler.
			if cfg.AuditPurgeInterval > 0 && cfg.AdminAuditRetentionDays > 0 {
				go runAdminEventsPurgeScheduler(ctx, cfg, deps.AuditRepo, adminAuditRepo, adminAuditRecorder)
			}
		},
	}
}

// runAuditPurgeScheduler — PR-A: периодический purge audit_logs.
// Пишет admin_event для каждого запуска (success/failure).
func runAuditPurgeScheduler(ctx context.Context, cfg *config.Config, auditSvc *audit.Service, adminAuditSvc adminaudit.Recorder) {
	log.Printf("audit-purge scheduler: interval=%s retention=%d days chunk=%d",
		cfg.AuditPurgeInterval, cfg.AuditRetentionDays, cfg.AuditPurgeChunkSize)
	ticker := time.NewTicker(cfg.AuditPurgeInterval)
	defer ticker.Stop()
	repo := auditSvc.GetRepo()
	purge := func() {
		cutoff := time.Now().UTC().Add(-time.Duration(cfg.AuditRetentionDays) * 24 * time.Hour)
		rctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
		deleted, err := repo.PurgeOlderThan(rctx, cutoff, cfg.AuditPurgeChunkSize)
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
		if err := repo.RecordPurgeRun(rctx, cutoff, deleted, audit.PurgeTargetAuditLogs); err != nil {
			log.Printf("audit-purge scheduler: record run failed: %v", err)
		}
		log.Printf("audit-purge scheduler: deleted %d rows (cutoff=%s)", deleted, cutoff.Format(time.RFC3339))
		adminAuditSvc.Record(rctx, adminaudit.Event{
			ActorUserID: nil, Action: "purge", Resource: "audit_logs",
			Path: "scheduler", Method: "INTERNAL", Success: true,
			Metadata: map[string]any{
				"mode": "scheduler", "cutoff": cutoff.Format(time.RFC3339),
				"rows_deleted": deleted,
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
		deleted, err := adminAuditRepo.PurgeOlderThan(rctx, cutoff, cfg.AuditPurgeChunkSize)
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
		if err := auditRepoHandle.RecordPurgeRun(rctx, cutoff, deleted, adminaudit.PurgeTarget); err != nil {
			log.Printf("admin-events purge scheduler: record run failed: %v", err)
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

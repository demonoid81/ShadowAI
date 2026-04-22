//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// Compiled only under -tags enterprise.

package main

import (
	"context"
	"fmt"
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
			// PR-L2.3: 4-eyes workflow — create делает pending,
			// approve/reject нужны для transition → active/released.
			admin.HandleFunc("/legal-holds", legalHoldHandler.Create).Methods("POST")
			admin.HandleFunc("/legal-holds", legalHoldHandler.List).Methods("GET")
			admin.HandleFunc("/legal-holds/{id}/approve", legalHoldHandler.Approve).Methods("POST")
			admin.HandleFunc("/legal-holds/{id}/reject", legalHoldHandler.Reject).Methods("POST")
			admin.HandleFunc("/legal-holds/{id}/release", legalHoldHandler.Release).Methods("POST")
		},

		StartSchedulers: func(ctx context.Context, cfg *config.Config) {
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

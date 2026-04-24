package main

// Licensing split for cmd/shadowai (see ENTERPRISE.md):
//
//   - enterprise.go (this file) — Apache License 2.0. Shared type +
//     bundle interface used by main.go. Depends only on core types
//     (adminaudit.Recorder, governance.Evaluator, auth.Eraser).
//
//   - enterprise_wire.go (//go:build enterprise) — full wiring for
//     admin_event_logs, governance CRUD, DSAR, purge schedulers,
//     enterprise route registration. Covered by LICENSE.enterprise.
//
//   - enterprise_stubs.go (//go:build !enterprise) — no-op stubs
//     that return a bundle with nil services and empty callbacks.
//     Covered by Apache License 2.0. Allows `go build ./...` to
//     succeed without any enterprise code in the binary.

import (
	"context"
	"database/sql"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/budget"
	"github.com/shadowai/backend/internal/config"
	"github.com/shadowai/backend/internal/governance"
)

// enterpriseBundle — всё, что Enterprise-сборка предоставляет поверх
// Core. Ни одно поле не обязательное — Core-билд получает полностью
// заполненный bundle с nil-сервисами и no-op callback'ами, поэтому
// main.go работает одинаково под обоими tag'ами.
type enterpriseBundle struct {
	// Core-interfaces (Apache 2.0 types), nil в Core-билде:
	AdminAudit adminaudit.Recorder  // admin_event_logs writer
	Governance governance.Evaluator // Provider/Model policy evaluator
	Eraser     auth.Eraser          // DSAR orchestration

	// RegisterRoutes добавляет enterprise-only admin routes:
	//   GET  /admin-events
	//   GET  /governance/policy
	//   PUT  /governance/policy
	//   POST /users/{id}/erase
	// В Core-билде — no-op: endpoints физически отсутствуют.
	RegisterRoutes func(admin *mux.Router, authHandler *auth.Handler)

	// StartSchedulers запускает goroutine'ы для retention/purge
	// (audit_logs retention + admin_event_logs retention). В Core —
	// no-op (retention выключен на уровне product model).
	StartSchedulers func(ctx context.Context, cfg *config.Config)

	// AnchorExtraTables — PR-W3: enterprise-only таблицы, которые
	// добавляются к anchor scheduler'у (main.go включает core tables
	// audit_logs + audit_purge_runs; enterprise добавляет свои).
	AnchorExtraTables []string

	// RegisterPublicRoutes добавляет enterprise-only public routes
	// (без AuthMiddleware), например OIDC login/callback.
	// В Core-билде — no-op.
	RegisterPublicRoutes func(publicAuth *mux.Router)
}

// enterpriseDeps — входные данные, которые wire получает от main,
// чтобы строить Services. AuditRepo / BudgetRepo — concrete
// *Repository (satisfy enterprise-specific AuditScrubber /
// BudgetDeleter interfaces из auth/erasure.go).
type enterpriseDeps struct {
	DB         *sql.DB
	Cfg        *config.Config
	AuditRepo  *audit.Repository
	BudgetRepo *budget.Repository
	AuditSvc   *audit.Service
	// PR-E1: OIDC user sync needs the auth repository and service.
	AuthRepo   *auth.Repository
	AuthSvc    *auth.Service
}

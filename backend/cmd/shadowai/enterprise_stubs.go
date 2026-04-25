//go:build !enterprise

package main

import (
	"context"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/config"
)

// buildEnterpriseBundle (Core-build) возвращает bundle с nil-сервисами
// и no-op callback'ами. Ни один enterprise-пакет не импортируется и не
// линкуется в бинарник `go build ./cmd/shadowai`.
//
// Compliance: acceptance criteria #3 для L-1 — в Core-билде нет
// /api/governance/policy, /api/admin-events, /users/{id}/erase,
// и нет retention-schedulers.
func buildEnterpriseBundle(_ enterpriseDeps) *enterpriseBundle {
	return &enterpriseBundle{
		AdminAudit: nil,
		Governance: nil,
		Eraser:     nil,
		RegisterRoutes:       func(_ *mux.Router, _ *auth.Handler) {},
		RegisterPublicRoutes: func(_ *mux.Router) {},
		RegisterMFARoutes:    func(_ *mux.Router) {},
		RegisterSCIMRoutes:   func(_ *mux.Router) {},
		StartSchedulers:      func(_ context.Context, _ *config.Config) {},
	}
}

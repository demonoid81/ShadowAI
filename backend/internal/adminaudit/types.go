// Package adminaudit exposes a core data contract (Event + Recorder)
// and an enterprise-only implementation (Service, Repository,
// Handler).
//
// Licensing split (see ENTERPRISE.md):
//
//   - types.go (this file) — Apache License 2.0. Core handlers depend
//     only on these type definitions so that they build and run
//     without any enterprise package present.
//
//   - service.go, repository.go, handler.go — covered by
//     LICENSE.enterprise. These files are compiled only when the
//     `enterprise` build tag is set.
//
// Core-only build supplies nil for Recorder; Record calls are already
// guarded by nil-checks in every core handler (auth, audit,
// dashboard, internaldb, governance).
package adminaudit

import (
	"context"

	"github.com/shadowai/backend/internal/domain"
)

// orgCtxKey is the context key for per-request org_id set by auth middleware.
type orgCtxKey struct{}

// orgValue is a typed marker to distinguish "not set" from "explicitly empty" (break-glass).
type orgValue struct{ org string }

// SetOrgContext injects orgID into context. Called by auth.AuthMiddleware after
// claims are resolved — avoids an import cycle (adminaudit ↔ auth).
// Break-glass sessions pass orgID="" which is preserved (means global, no org filter).
func SetOrgContext(ctx context.Context, orgID string) context.Context {
	return context.WithValue(ctx, orgCtxKey{}, orgValue{org: orgID})
}

// GetOrgFromContext returns orgID previously set by SetOrgContext.
// Returns empty string for break-glass / global_admin sessions (OrgID="" was explicitly set).
// Falls back to domain.DefaultOrgID only when SetOrgContext was never called (unprotected path).
func GetOrgFromContext(ctx context.Context) string {
	if m, ok := ctx.Value(orgCtxKey{}).(orgValue); ok {
		return m.org // "" = break-glass/global; non-empty = tenant org
	}
	return domain.DefaultOrgID
}

// Event — данные, которые caller передаёт в Recorder. JSON-encoding
// выполняется в enterprise-реализации (Service).
type Event struct {
	ActorUserID  *string
	Action       string
	Resource     string
	TargetID     string
	Path         string
	Method       string
	StatusCode   int
	Success      bool
	Metadata     any
	// PR-T2.3.1: tenant isolation. OrgID is populated automatically from context
	// by Service.Record; callers may override SourceOrgID/TargetOrgID for cross-org events.
	OrgID        string
	SourceOrgID  string
	TargetOrgID  string
}

// Recorder — интерфейс для DI в core handler'ах. Enterprise-сборка
// передаёт *Service; core-сборка передаёт nil.
type Recorder interface {
	Record(ctx context.Context, ev Event)
}

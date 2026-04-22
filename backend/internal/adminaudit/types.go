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

import "context"

// Event — данные, которые caller передаёт в Recorder. JSON-encoding
// выполняется в enterprise-реализации (Service).
type Event struct {
	ActorUserID *string
	Action      string
	Resource    string
	TargetID    string
	Path        string
	Method      string
	StatusCode  int
	Success     bool
	Metadata    any
}

// Recorder — интерфейс для DI в core handler'ах. Enterprise-сборка
// передаёт *Service; core-сборка передаёт nil.
type Recorder interface {
	Record(ctx context.Context, ev Event)
}

## What changed and why

<!-- Describe the change and the motivation. Reference issues/PRs. -->

## Type

- [ ] feat — new feature
- [ ] fix — bug fix
- [ ] docs — documentation only
- [ ] refactor — no functional change
- [ ] test — tests only
- [ ] chore — build/CI/infra

## Checklist

### Code
- [ ] `go test ./... -count=1` green (core)
- [ ] `go test -tags enterprise ./... -count=1` green (enterprise)
- [ ] `go build ./... && go build -tags enterprise ./...` clean

### Security-sensitive changes
If this PR touches auth, governance, audit, SCIM, OIDC, MFA, or break-glass:
- [ ] No new PII in admin_event_logs metadata
- [ ] No secret values in audit/log output
- [ ] prod validation updated if new env vars added
- [ ] Enterprise-only features behind `//go:build enterprise`

### DB migrations
- [ ] Migration is additive (no DROP, no NOT NULL without DEFAULT)
- [ ] Migration number is sequential (`backend/migrations/NNN_*.sql` or `migrations-enterprise/NNN_*.sql`)
- [ ] Idempotent (safe to run twice)

### Enterprise split
- [ ] Apache 2.0 types in un-tagged files; enterprise logic in `//go:build enterprise` files
- [ ] `go build ./...` (no enterprise tag) still compiles without errors

### Tests
- [ ] New behavior covered by unit tests
- [ ] No `t.Skip()` without explanation
- [ ] No test-only mocks leaking into production code

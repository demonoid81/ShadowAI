# ShadowAI Enterprise Components

This repository is **dual-licensed**:

- The bulk of the code (proxy, firewall, inspectors, benchmark
  harness, basic auth/policy/budget/dashboard) is licensed under the
  **Apache License 2.0** — see [LICENSE](LICENSE).
- Specific directories and files listed below — the "Enterprise
  Components" — are licensed under a **proprietary commercial
  license** — see [LICENSE.enterprise](LICENSE.enterprise).

Reading the source of Enterprise Components is free. **Using them in
production requires a commercial agreement** with the ShadowAI
Contributors.

## Scope of Enterprise Components

The following paths are covered by [LICENSE.enterprise](LICENSE.enterprise):

### Go packages (entire directory)

- `backend/internal/adminaudit/` — admin access audit
  infrastructure (admin_event_logs, retention, privacy-preserving
  metadata).
- `backend/internal/governance/` — Provider/Model Governance
  (allowlist, deny-by-default, policy visibility, policy deny
  events).

### Individual Go files

- `backend/internal/auth/erasure.go` — DSAR / GDPR-erasure
  orchestration service.
- `backend/internal/auth/erasure_test.go`
- `backend/internal/auth/user_read_audit_test.go` — admin-read
  access audit test for `GET /api/users/{id}`.

### SQL migrations

- `backend/migrations/009_create_user_erasure_runs.sql` — DSAR
  tombstone table.
- `backend/migrations/010_create_admin_event_logs.sql` — admin
  event log storage.
- `backend/migrations/011_add_target_to_audit_purge_runs.sql` —
  retention target column for admin-events vs user-audit.
- `backend/migrations/012_create_provider_governance_policies.sql`
  — governance policy singleton table.

### Documentation

- `docs/privacy-ops-runbook.md` — operator guide covering DSAR,
  retention, backup scrub, admin-audit, incident workflow.

### Commands / CLIs

- `backend/cmd/audit-purge/` — retention purge CLI used against
  enterprise retention features.

## Integration hooks in Core (Apache 2.0)

A small number of lines in Core files wire the Enterprise
Components into the proxy and dashboard pipelines (for example,
`proxy.NewHandler` accepts `*governance.Service` and
`adminaudit.Recorder`, and writes `admin_event_logs` on policy
deny). These hook lines are covered by the **Apache License 2.0**
because the wiring logic belongs in Core; however, passing `nil`
leaves Core fully functional without any Enterprise Components,
and no runtime dependency is created by the hook lines themselves.

Writing or modifying these hook lines does not require a commercial
license. Running a build that *uses* the Enterprise Components does.

## What this means in practice

### Reading the source
Anyone may clone this repository, read all files (Core and
Enterprise), study the architecture, and discuss it.

### Running Core only
You may build and run ShadowAI with the Enterprise Components
excluded from the binary (for example, with `-tags noenterprise`
build tags once such tags are added, or by manually removing
enterprise imports). Running Core alone falls fully under Apache
2.0 and requires no commercial agreement.

A reference build configuration for Core-only will be documented
separately as enterprise components mature. Until then, the
straightforward path is to obtain a commercial license for the full
build if you need the enterprise features.

### Running the full build (Core + Enterprise)
Requires a commercial agreement (MSA + Order Form + Self-Hosted
EULA). See `LICENSE.enterprise` and contact the maintainers.

### Providing a hosted "-as-a-service" offering
- If it is Core-only (no Enterprise Components compiled in),
  Apache 2.0 terms apply. Trademark policy ([TRADEMARK.md](TRADEMARK.md))
  still forbids naming such a service "ShadowAI" without written
  permission.
- If it includes Enterprise Components, this is **prohibited by
  `LICENSE.enterprise`** regardless of any other license.

## Contributing

- Contributions to Core paths follow the **DCO** workflow described
  in [CONTRIBUTING.md](CONTRIBUTING.md).
- Contributions to Enterprise paths additionally require a signed
  **Contributor License Agreement (CLA)**. CI will flag PRs touching
  enterprise paths and request CLA signature before merge.

The reason for the different workflow: Enterprise Components are
licensed under a non-OSS license that only the copyright holder can
grant. Contributions need an explicit CLA so the Enterprise line
remains re-licensable by ShadowAI Contributors.

## Moving components between lines

If a feature currently inside an Enterprise Component is later
relicensed to Apache 2.0 (for example, because it matures into a
standard feature or due to a strategic decision), the corresponding
entry is removed from the list above and a changelog entry is added
to `CHANGELOG.md`. Relicensing in the reverse direction (Apache →
Enterprise) will **not** happen for any code that has ever been
released under Apache; that would undermine the Apache grant.

## Disclaimer

This document is a project-level statement of intent regarding
licensing boundaries. It is not legal advice. Formal commercial
terms are those of the signed MSA and related agreements.

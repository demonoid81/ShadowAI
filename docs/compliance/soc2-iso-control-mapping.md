# ShadowAI — SOC 2 / ISO 27001 Control Evidence Inventory

**Version:** v1 · **Date:** 2026-04-26 · **Status:** Readiness mapping — not a certification

---

## Disclaimer

> **This document is a control evidence inventory prepared for internal audit
> readiness and security questionnaire support. It is NOT a SOC 2 audit report,
> NOT a SOC 2 Type I or Type II opinion, and NOT an ISO 27001 certification or
> attestation. No third-party auditor has reviewed or attested to the contents
> of this document. Controls described here reflect the current implemented
> state of the ShadowAI platform; residual gaps are explicitly noted.**
>
> Suitable use: security questionnaires, vendor assessments, pre-audit gap
> analysis, internal readiness reviews. Not suitable use: customer-facing
> compliance claims without independent audit, legal attestation, or regulatory
> filings.

---

## Overview

This inventory maps ShadowAI platform controls to relevant SOC 2 Trust Service
Criteria (TSC) and ISO 27001:2022 control domains. For each control category,
it describes:

- **Control objective** — what the control is intended to achieve.
- **ShadowAI implementation** — the specific technical mechanism(s) in place.
- **Evidence artifact** — where reviewers can find proof of control operation.
- **Owner** — the team or role responsible for the control.
- **Cadence** — how frequently the control is exercised or evidence is collected.
- **Residual gap** — honest description of what is not yet covered.

### SOC 2 TSC Reference

| TSC | Title |
|-----|-------|
| CC6.1–CC6.8 | Logical and Physical Access |
| CC7.1–CC7.5 | System Operations |
| CC8.1 | Change Management |
| CC9.1–CC9.2 | Risk Mitigation / Vendor Management |
| A1.1–A1.3 | Availability |
| C1.1–C1.2 | Confidentiality |

### ISO 27001:2022 Reference

| Domain | Title |
|--------|-------|
| A.5 | Organizational controls |
| A.8 | Technological controls |
| A.8.2 | Privileged access rights |
| A.8.15 | Logging |
| A.8.16 | Monitoring |
| A.8.23 | Web filtering / provider governance |
| A.8.32 | Change management |

---

## 1. Access Control / Identity

**SOC 2:** CC6.1, CC6.2, CC6.3  
**ISO 27001:** A.8.2, A.8.3, A.8.5

| Field | Detail |
|-------|--------|
| **Control objective** | Only authenticated and authorised identities can access the system. User roles and attributes are sourced from a trusted identity provider. |
| **Implementation** | OIDC authorization code flow with configurable issuer. Claims mapped to role, email, department. Local break-glass admin account behind explicit `BREAK_GLASS_ENABLED` env var. Startup fail-fast if MFA policy not configured in production mode. Session tokens invalidated on SCIM-driven deprovisioning. |
| **Evidence artifacts** | `admin_event_logs` rows for every login success/fail, OIDC config change, role sync change; SIEM mirror delivers events in real time. Auth config in `internal/auth/` and `internal/oidc/`. |
| **Owner** | Platform / security team |
| **Cadence** | Continuous (every login/change). SCIM sync on IdP push. |
| **Residual gap** | SAML not supported (OIDC only). IdP-side MFA enforcement is operator responsibility; ShadowAI enforces `amr`/`acr` claim presence, not MFA strength. No session timeout currently configurable beyond JWT expiry. |

---

## 2. Privileged Access / Break-Glass

**SOC 2:** CC6.3, CC6.8  
**ISO 27001:** A.8.2, A.5.18

| Field | Detail |
|-------|--------|
| **Control objective** | Privileged (admin) access is controlled, audited, and time-limited in emergency break-glass scenarios. |
| **Implementation** | Admin routes require `role=admin` or `global_admin` org membership. Break-glass local account enabled only with `BREAK_GLASS_ENABLED=true` (startup warning if set in prod). Every admin action writes an `admin_event_log` row with actor, action, target, org context. Global admin org provides cross-tenant administrative control plane. |
| **Evidence artifacts** | `admin_event_logs` table; admin events forwarded to SIEM. Break-glass usage queryable: `SELECT * FROM admin_event_logs WHERE auth_method='break_glass'`. Runbook: `docs/evidence-export-runbook.md`. |
| **Owner** | Platform / security team |
| **Cadence** | Continuous audit trail. Break-glass usage review: operator-defined (recommended: weekly). |
| **Residual gap** | No automated alert on break-glass usage (must be queried manually or via SIEM filter). No time-bound admin session / MFA step-up specifically for break-glass path. |

---

## 3. Audit Logging

**SOC 2:** CC7.2, CC7.3  
**ISO 27001:** A.8.15, A.8.16

| Field | Detail |
|-------|--------|
| **Control objective** | All security-relevant events are logged with sufficient detail for forensic reconstruction, tamper-evident, and retained per policy. |
| **Implementation** | `audit_logs` table captures every LLM proxy request: user, org, provider, model, policy decision, token counts, status. HMAC chain links rows (chain secret per deploy). `admin_event_logs` captures all administrative actions. `user_erasure_runs` records DSAR operations. Org-scoped: all logs carry `org_id`. |
| **Evidence artifacts** | `audit_logs`, `admin_event_logs`, `user_erasure_runs` tables. Chain verification: `audit-verify --table audit_logs --verbose`. SIEM HTTP mirror delivers events in real time. Evidence bundle: offline signed export via `audit-export-evidence`. |
| **Owner** | Platform team |
| **Cadence** | Continuous (per-request). Nightly bundle export. SIEM delivery: async with retry/backpressure. |
| **Residual gap** | Log retention enforcement is operator-configured (`AUDIT_RETENTION_DAYS`); ShadowAI purges rows but does not independently enforce a minimum retention floor. No read-access audit log (i.e., who queried audit logs is not itself logged). |

---

## 4. Evidence Integrity / WORM

**SOC 2:** CC7.3, CC9.1  
**ISO 27001:** A.8.10, A.8.15

| Field | Detail |
|-------|--------|
| **Control objective** | Audit evidence cannot be tampered with or deleted after creation. Evidence bundles are verifiable offline by a third-party auditor without database access. |
| **Implementation** | HMAC chain (`AUDIT_CHAIN_SECRET`) links every `audit_log` row to its predecessor — any gap or modification is detectable. Merkle anchor scheduler creates signed anchors (`Ed25519`) over batches of rows; anchors are checkpointed to file and optionally to immudb (append-only ledger). Evidence bundles (`.zip`) contain chain hashes, Merkle proofs, anchor signatures, SHA256 file manifest. S3 Object Lock (`COMPLIANCE` / `GOVERNANCE` mode) makes uploaded bundles WORM-protected. Tenant bundles include Merkle inclusion proofs without exposing cross-tenant row hashes. |
| **Evidence artifacts** | `audit_chain_anchors` table. Anchor checkpoint files (`anchors.ndjson`). Evidence bundle: `audit-export-evidence --global` or `--org-id`. Offline verification: `audit-verify --bundle <dir> --verbose`. Retention posture: `audit-evidence-report --bucket ... --require-lock --min-retention-days 90`. S3 Object Lock metadata: `aws s3api head-object ...` (see runbook §2). |
| **Owner** | Platform team |
| **Cadence** | Chain: continuous (per insert). Anchor scheduler: configurable batch interval. Evidence bundle: nightly CronJob. Retention posture report: weekly CronJob (`evidence-audit-report`). |
| **Residual gap** | Key rotation for `AUDIT_CHAIN_SECRET` and Ed25519 signing keys is manual / not automated (W7 roadmap item). Only one immudb sink in default configuration; second independent anchor sink is documented as a roadmap item. Restore verification drill is manual (runbook §6); no automated scheduled drill. |

---

## 5. Data Retention, Deletion and Legal Hold

**SOC 2:** C1.1, C1.2  
**ISO 27001:** A.8.10, A.5.34

| Field | Detail |
|-------|--------|
| **Control objective** | Personal data is retained only as long as required. Users can request erasure. Legal holds prevent premature deletion of data subject to regulatory or legal requirements. |
| **Implementation** | Configurable retention (`AUDIT_RETENTION_DAYS`) with automatic purge. DSAR (right-to-erasure): `POST /auth/erase` initiates anonymization, creates `user_erasure_runs` record, respects active holds. Legal hold (L1-L4): 4-eyes apply workflow, active hold blocks DSAR, retention-aware purge skips held users, advisory-lock prevents concurrent conflicting operations. Hold state tracked in `legal_holds` table with actor, timestamps, and reason. |
| **Evidence artifacts** | `user_erasure_runs` table. `legal_holds` table. `admin_event_logs` for hold apply/release events. Erasure audit trail in `audit_logs` via `policy_action='erasure_*'`. |
| **Owner** | Platform / legal / DPO |
| **Cadence** | Purge: configurable interval. Erasure: on-demand. Hold status: continuous. |
| **Residual gap** | Legal hold scope is currently whole-user only (not date-range or query-scope). No automated SLA escalation for hold durations. Bulk hold approval/release is manual. No automated notification to DPO on DSAR submission. |

---

## 6. Tenant Isolation

**SOC 2:** CC6.3, CC6.6  
**ISO 27001:** A.8.3, A.5.15

| Field | Detail |
|-------|--------|
| **Control objective** | Data belonging to one tenant (organisation) cannot be accessed by another tenant at runtime, in logs, in exports, or via administrative interfaces. |
| **Implementation** | `org_id` column present on all user-facing tables: `users`, `audit_logs`, `admin_event_logs`, `budgets`, `provider_governance_policies`, `legal_holds`, `user_erasure_runs`, `scim_tokens`. All repository methods filter by `org_id` from authenticated JWT claims. Admin APIs enforce org-scoped access. Global admin org (`global_admin=true`) provides cross-tenant control plane with its own audit trail. Tenant evidence bundles use Merkle inclusion proofs that exclude cross-tenant row hashes. SCIM tokens are per-org, not global. |
| **Evidence artifacts** | Database schema migrations (`migrations/`). Org-scoped query patterns in `internal/*/repository.go`. Tenant bundle proof output: `audit-verify --bundle <tenant-bundle-dir> --verbose`. Smoke test: `backend/smoke/t2_tenant_isolation_smoke_test.go`. |
| **Owner** | Platform team |
| **Cadence** | Continuous (runtime enforcement). Smoke tests on every CI run. |
| **Residual gap** | No formal penetration test or third-party tenant isolation assessment. Row-level security not enforced at the database layer (enforcement is in application code only). Single-database deployment: no physical DB-level tenant separation. |

---

## 7. Vendor / Provider Governance

**SOC 2:** CC9.2  
**ISO 27001:** A.5.19, A.5.21, A.8.23

| Field | Detail |
|-------|--------|
| **Control objective** | LLM provider and model usage is governed by explicit policy. Unapproved provider/model combinations are denied before the request reaches the LLM API. |
| **Implementation** | Per-org governance policy with modes: `disabled`, `allowlist_strict`, `role_based`, `context_scoped`. Proxy enforces policy on every request (in-process cache post G2.2 — DB-free hot path). `allowlist_strict`: only explicitly approved (provider, model) pairs allowed. `role_based`: per-role allowlists. `context_scoped`: (department, sensitivity, role) → allowlist. Deny-by-default for all modes except `disabled`. All governance decisions logged in `audit_logs` with `policy_action` field. LLM firewall (F7/F8) provides streaming content inspection and shadow semantic evaluation. |
| **Evidence artifacts** | `provider_governance_policies` table. `audit_logs.policy_action` field. Governance decision code in audit events: `allowed`, `unknown_provider`, `unknown_model`, `unknown_role`, `sensitivity_denied`. Policy admin API: `PUT /governance/policy`. Prometheus metric: `shadowai_governance_cache_hits_total`. |
| **Owner** | Platform / security / compliance team |
| **Cadence** | Continuous (per-request enforcement). Policy changes: admin action with audit trail. |
| **Residual gap** | No third-party SSPM (SaaS Security Posture Management) integration. Policy export/report (full policy history across orgs) not available as a report — only queryable via DB. `semantic_v2` semantic evaluation is shadow-only by default (not enforced in production without operator gate). |

---

## 8. Security Monitoring / SIEM

**SOC 2:** CC7.2, CC7.3  
**ISO 27001:** A.8.15, A.8.16

| Field | Detail |
|-------|--------|
| **Control objective** | Security-relevant events are forwarded to an external SIEM in real time. Delivery is reliable with retry and backpressure. |
| **Implementation** | SIEM HTTP mirror (S1/S1.1): every `audit_log` write triggers an async SIEM delivery attempt. Async queue with configurable capacity, batching, retry (configurable max retries), backpressure policy (drop-oldest / drop-newest), graceful drain on shutdown. Delivery metrics: `shadowai_siem_requests_total`, `shadowai_siem_fail_total`, `shadowai_siem_timeout_total`, `shadowai_siem_queue_depth`, `shadowai_siem_dropped_total`, `shadowai_siem_retry_total`. |
| **Evidence artifacts** | SIEM delivery metrics in Prometheus/Grafana. `audit_logs` mirrored to external SIEM endpoint. SIEM configuration: env vars `SIEM_ENDPOINT`, `SIEM_BATCH_SIZE`, `SIEM_FLUSH_INTERVAL`, `SIEM_MAX_RETRIES`. |
| **Owner** | Platform / security ops team |
| **Cadence** | Continuous (per audit event). |
| **Residual gap** | SIEM endpoint, authentication, and TLS configuration are operator-managed — no built-in SIEM health check or alert on prolonged delivery failure. `shadowai_siem_dropped_total > 0` alerts are documented as operator configuration (Prometheus alerting rules must be set up separately). No built-in SIEM format normalization (CEF, LEEF, etc.) — raw JSON events. |

---

## 9. Incident Response / Operations

**SOC 2:** CC7.3, CC7.4, CC7.5  
**ISO 27001:** A.5.24, A.5.26

| Field | Detail |
|-------|--------|
| **Control objective** | Operational incidents are detected via automated alerting. Evidence export failures are alerted. Runbooks guide operator response. |
| **Implementation** | Prometheus alerting rules (PrometheusRule CRD): `EvidenceExportJobFailed`, `EvidenceExportJobMissing` for nightly bundle export; `EvidenceAuditReportJobFailed`, `EvidenceAuditReportJobMissing` for weekly retention posture check. Health and readiness endpoints (`/healthz`, `/readyz`). Structured logging for all operational events. Operator runbooks: `docs/evidence-export-runbook.md` (evidence pipeline), `docs/production-checklist.md`. |
| **Evidence artifacts** | PrometheusRule YAML in `deploy/helm/shadowai/templates/prometheusrule.yaml`. Runbooks in `docs/`. Alert firing evidence in Prometheus/Alertmanager. |
| **Owner** | Platform / SRE team |
| **Cadence** | Continuous (alerting). Weekly (retention posture CronJob). Nightly (evidence export CronJob). |
| **Residual gap** | No dedicated incident management integration (PagerDuty, OpsGenie, etc.) — operator must configure alerting routing. No formal incident response runbook for security incidents (e.g., suspected tamper, data breach). Alert coverage for SIEM queue/drop/retry and semantic_v2 `fail_open` dashboards is documented but requires operator Prometheus setup. |

---

## 10. Change Management / CI

**SOC 2:** CC8.1  
**ISO 27001:** A.8.32

| Field | Detail |
|-------|--------|
| **Control objective** | Code changes are reviewed, tested, and deployed through a controlled pipeline. Breaking changes to security controls are gated by automated tests. |
| **Implementation** | GitHub Actions CI pipeline runs on every PR and push to master: unit tests (core + enterprise), integration tests (httptest fake S3, no Docker dependency), enterprise smoke tests (real PG + Redis via testcontainers), security scan, Docker build, Helm lint + render validation, CLI build gate. `make helm-validate` validates Helm chart before deploy. Database migrations are versioned (`migrations/` and `migrations-enterprise/`) with init-container runner. Fail-fast startup config guard rejects unsafe production configurations. |
| **Evidence artifacts** | `.github/workflows/ci.yml`. CI run history in GitHub Actions. `Makefile` targets: `build`, `build-enterprise`, `build-cli`, `helm-validate`. |
| **Owner** | Platform / engineering team |
| **Cadence** | Every PR and push. |
| **Residual gap** | No mandatory two-person review enforced at GitHub repo level (branch protection rules are operator-managed). No SAST (Static Application Security Testing) tool integrated in CI. No dependency vulnerability scanning (SCA) integrated in CI. Deployment pipeline beyond CI is manual (Helm install/upgrade by operator). |

---

## Current Gaps / Not Covered

The following areas are not currently covered by implemented controls. They
represent honest residual risks that should be addressed before a formal SOC 2
audit engagement.

| Gap | Category | Notes |
|-----|----------|-------|
| Formal penetration test / third-party tenant isolation assessment | Tenant isolation, CC6.3 | Product-complete in code; not independently verified |
| SOC 2 Type I / II audit engagement | All | No third-party auditor engaged |
| ISO 27001 certification | All | No certification body engaged |
| Automated SIEM delivery failure alert | Security monitoring | Prometheus rule must be operator-configured |
| Key rotation automation for chain secret / Ed25519 signing key | Evidence integrity | Manual runbook; W7 roadmap item |
| Automated restore verification drill | Evidence integrity, A1.3 | Manual runbook; W7 roadmap item |
| Independent second anchor sink | Evidence integrity | Single immudb sink; optional second sink in roadmap |
| Legal hold scope beyond whole-user | Data retention | Date-range / query-scope holds in roadmap (L5) |
| SAST / SCA in CI | Change management | Not integrated; operator can add |
| Two-person code review enforcement | Change management | GitHub branch protection: operator-managed |
| Database-layer row-level security | Tenant isolation | Application-level only |
| SAML IdP support | Access control | OIDC only |
| Formal Security Policy documentation | A.5.1 | Technical controls exist; policy document not yet written |
| Business Continuity / Disaster Recovery plan | A.5.30 | DB backup/restore drill documented; formal BCP not written |
| Vendor assessment for LLM providers | CC9.2 | Governance policy controls usage; no formal TPRM process |
| BYOK / customer-managed encryption | C1.2 | Roadmap; not yet implemented |

---

## How to Use in Security Questionnaire

When completing a vendor security questionnaire or responding to a customer
security review, use the following guidance:

### Access Management questions

Point to §1 (OIDC, MFA claim enforcement, role mapping, break-glass audit),
§2 (privileged access, `admin_event_logs`). Be clear that MFA enforcement at
the IdP level is an operator configuration responsibility.

### Audit Logging / Log Integrity questions

Point to §3 (immutable `audit_logs` with HMAC chain) and §4 (Merkle anchors,
Ed25519 signatures, S3 Object Lock). Evidence bundles can be verified offline
by the questioner's auditor using `audit-verify --bundle <dir> --verbose`.

### Data Residency / Retention / Deletion questions

Point to §5 (configurable retention, DSAR/erasure, legal hold). Be explicit
that retention floor is operator-configured; ShadowAI enforces the configured
policy, not a fixed minimum.

### Multi-tenancy / Data Isolation questions

Point to §6 (org-scoped rows on all tables, application-layer enforcement). Be
explicit that **no formal penetration test has been conducted** and that
row-level security is application-level only.

### Security Monitoring questions

Point to §8 (SIEM HTTP mirror, retry/backpressure, Prometheus metrics). Be
clear that SIEM endpoint configuration and alerting routing are operator
responsibilities.

### Incident Response questions

Point to §9 (Prometheus alerts, runbooks). Be explicit that no third-party
incident management integration is built-in.

### Third-Party / Vendor Controls questions

Point to §7 (per-org governance policy, deny-by-default allowlist, policy
audit trail). Note that third-party risk management (TPRM) for LLM providers
is not formally implemented.

### What NOT to say

- Do not say "SOC 2 compliant" — ShadowAI has not been audited.
- Do not say "ISO 27001 certified" — ShadowAI has not been certified.
- Do not promise automated alerts without confirming operator Prometheus setup.
- Do not reference W7 (key rotation) or BYOK as current controls.

---

## Evidence Artifact Quick Reference

| Artifact | Location | Purpose |
|----------|----------|---------|
| Audit log chain verification | `audit-verify --table audit_logs` | Tamper detection on DB rows |
| Evidence bundle (global) | `audit-export-evidence --global --output <dir>` | Offline audit evidence |
| Evidence bundle (tenant) | `audit-export-evidence --org-id <uuid>` | Tenant-scoped audit evidence |
| Bundle offline verify | `audit-verify --bundle <dir> --verbose` | Auditor verification without DB |
| S3 retention posture | `audit-evidence-report --bucket ... --require-lock` | WORM retention coverage |
| Admin event trail | `SELECT * FROM admin_event_logs WHERE ...` | Privileged action audit |
| SIEM delivery metrics | Prometheus `shadowai_siem_*` | SIEM reliability evidence |
| Governance policy | `GET /governance/policy` (admin) | Approved provider/model list |
| Legal hold status | `GET /legal-holds` (admin) | Active holds and hold log |
| CI pipeline | `.github/workflows/ci.yml` | Change control evidence |
| Helm chart validation | `make helm-validate` | Deployment gate evidence |

---

## Related Documents

- `docs/evidence-export-runbook.md` — Evidence pipeline operations, Object Lock setup, restore drill
- `docs/2026-04-17-enterprise-readiness-roadmap.md` — Roadmap and current implementation status
- `deploy/helm/shadowai/templates/prometheusrule.yaml` — Alert rules for evidence pipeline
- `backend/internal/governance/` — Governance policy implementation
- `backend/internal/audit/` — Audit log chain implementation
- `backend/smoke/` — Integration smoke tests (CI evidence)

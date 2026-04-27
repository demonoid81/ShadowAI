// templates.go — checklist templates for the quarterly evidence package.
package main

import "strings"

const (
	tplPeriodFrom = "{{PERIOD_FROM}}"
	tplPeriodTo   = "{{PERIOD_TO}}"
)

func fillTemplate(tpl, from, to string) string {
	r := strings.NewReplacer(tplPeriodFrom, from, tplPeriodTo, to)
	return r.Replace(tpl)
}

const accessReviewTpl = `# Access Review Checklist — {{PERIOD_FROM}} to {{PERIOD_TO}}

**Status:** [ ] Completed
**Reviewer:** ___________________
**Review date:** ___________________

---

## 1. Admin account inventory

| User ID | Role | MFA status | Last login | Action |
|---------|------|-----------|------------|--------|
| | | | | |

**Sign-off:** All admin accounts have been reviewed. Inactive accounts have been
deprovisioned or flagged for removal.

---

## 2. SCIM-provisioned users

- [ ] Verified no deprovisioned users retain active sessions
- [ ] SCIM token rotation completed if any tokens are > 90 days old
- [ ] Per-org SCIM tokens reviewed: no cross-tenant tokens in use

---

## 3. Break-glass admin account

- [ ] Break-glass account usage log reviewed for this period
- [ ] No unexpected use of break-glass during period (or incidents documented below)

Break-glass use during period: [ ] None / [ ] Documented — see incident log

---

## 4. OIDC / IdP review

- [ ] IdP MFA policy confirmed enforced for all admin routes
- [ ] Group-to-role mapping reviewed; no orphaned mappings

---

## 5. Legal hold review

- [ ] All active legal holds reviewed with legal team
- [ ] No holds pending approval for > 7 days (check: GET /api/legal-holds/pending-sla)
- [ ] All release requests in release_pending state reviewed

Holds active at end of period: ___ (run: GET /api/legal-holds)

---

## Notes

___________________
`

const incidentAlertReviewTpl = `# Incident and Alert Review Checklist — {{PERIOD_FROM}} to {{PERIOD_TO}}

**Status:** [ ] Completed
**Reviewer:** ___________________
**Review date:** ___________________

---

## 1. Prometheus alerts fired during period

| Alert | Fired at | Resolved at | Severity | Root cause | Action taken |
|-------|----------|-------------|----------|------------|--------------|
| | | | | | |

[ ] No alerts fired during this period

---

## 2. Evidence export job status

- [ ] EvidenceExportJobFailed: 0 firings during period
- [ ] EvidenceExportJobMissing: 0 firings during period
- [ ] EvidenceAuditReportJobFailed: 0 firings during period

Evidence export success rate for period: ____%%

---

## 3. SIEM delivery status

- [ ] SIEM dropped events: 0 (shadowai_siem_dropped_total delta for period)
- [ ] SIEM fail rate: < 0.1%% of deliveries
- [ ] SIEM endpoint availability: ____%%

---

## 4. Streaming / firewall incidents

- [ ] No unexpected mid-stream block spikes
- [ ] Sanitize events reviewed (if any): ___
- [ ] Shadow mismatch rate within threshold (< 0.5%%)

---

## 5. Audit chain integrity

- [ ] No chain breaks detected during restore drill
- [ ] Merkle anchor verification passed for all tables
- [ ] Evidence bundle offline verification: all bundles PASSED

Run: audit-verify --restore-drill --table all --pubkey-file <anchor-pubkey.b64> --verbose

---

## 6. Security incidents

[ ] No security incidents during period

| Incident | Date | Severity | Status | Reference |
|----------|------|----------|--------|-----------|
| | | | | |

---

## Notes

___________________
`

const ciReleaseChecklistTpl = `# CI / Release Checklist — {{PERIOD_FROM}} to {{PERIOD_TO}}

**Status:** [ ] Completed
**Reviewer:** ___________________
**Review date:** ___________________

---

## Releases deployed during period

| Version / commit | Deploy date | Rollback tested | Notes |
|-----------------|-------------|-----------------|-------|
| | | | |

---

## Change management checks

- [ ] All deployments triggered via CI pipeline (no manual kubectl apply)
- [ ] make helm-validate passed for each release
- [ ] go test -tags enterprise ./... passed on all release commits
- [ ] Smoke tests passed before promotion to production
- [ ] Database migrations applied via init container (no manual SQL)

---

## Security-relevant changes

- [ ] No new plaintext secrets introduced
- [ ] No SIEM_INSECURE_SKIP_VERIFY=true in production config
- [ ] STREAMING_ALLOW_INCREMENTAL_IN_PROD reviewed if set
- [ ] Governance policy changes documented and approved

---

## Dependency review

- [ ] No critical CVEs in base image (alpine:3.21 or later)
- [ ] Go dependencies: go mod tidy run; no known CVEs in direct dependencies

---

## Notes

___________________
`

func accessReviewChecklist(from, to string) string { return fillTemplate(accessReviewTpl, from, to) }
func incidentAlertReviewChecklist(from, to string) string {
	return fillTemplate(incidentAlertReviewTpl, from, to)
}
func ciReleaseChecklist(from, to string) string { return fillTemplate(ciReleaseChecklistTpl, from, to) }

# LLM Provider Vendor-Risk Process

Date: 2026-04-28
Status: VRM1 process package complete; legal/commercial due diligence remains operator-owned.

## 1. Purpose

ShadowAI enforces provider/model usage through per-org governance policies, but
that runtime control is not the same as a formal third-party risk management
process.

This document defines the vendor-risk workflow for LLM providers so a customer
or operator can answer vendor-risk questionnaires honestly:

- which providers are approved,
- why they were approved,
- which models are allowed for which departments/sensitivity levels,
- what evidence supports the approval,
- when the provider must be reviewed again,
- how governance policy must be updated after approval or revocation.

This process does not perform legal, procurement, privacy, or commercial vendor
due diligence on behalf of the operator.

## 2. Current Technical Controls

| Control | Current implementation |
|---------|------------------------|
| Provider/model allowlist | `provider_governance_policies.rules_json` |
| Role-based routing | `role_rules_json` |
| Department/sensitivity routing | `context_rules_json` |
| Runtime enforcement | Proxy denies disallowed provider/model before upstream call |
| Audit trail | `audit_logs.policy_action`, `admin_event_logs` for policy changes |
| Tenant boundary | Governance policy is scoped by `org_id` |
| Monitoring | Governance cache metrics and audit evidence |
| Evidence export | Governance policy and audit rows included in operator evidence workflow |

These controls reduce operational risk but do not prove that a provider's own
security, privacy, retention, or subprocessor controls are acceptable. That
approval must happen through the process below.

## 3. Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| Business owner | Explains use case, business need, data classes and expected volume |
| Security owner | Reviews security posture, incident response, logging and model abuse controls |
| Privacy/legal owner | Reviews DPA, data retention, subprocessors, region and deletion rights |
| Platform owner | Converts approval into ShadowAI governance policy |
| Compliance owner | Maintains the approved provider register and review cadence |

One person may hold multiple roles in a small deployment, but the approval
record should still name the accountable owner for each area.

## 4. Provider Lifecycle

### 4.1 Intake

Create one assessment file from
`docs/compliance/templates/llm-provider-assessment-template.md`.

Required intake fields:

- provider name,
- intended models,
- business use case,
- tenant/org scope,
- data sensitivity level,
- expected request/response data categories,
- hosting region,
- retention and training posture,
- requested go-live date.

### 4.2 Assessment

Complete the assessment checklist across five dimensions:

1. Security and compliance posture.
2. Data handling, retention and training controls.
3. Privacy, DPA, subprocessor and region controls.
4. Operational resilience and incident response.
5. ShadowAI governance mapping.

Do not mark a provider approved if the governance mapping is unknown. The
approval must be specific enough to produce an allowlist rule.

### 4.3 Approval Decision

Decision values:

| Decision | Meaning |
|----------|---------|
| `approved` | Provider/model can be used under documented constraints |
| `conditional` | Provider/model allowed only with explicit restrictions and follow-up date |
| `denied` | Provider/model cannot be used |
| `expired` | Previous approval is past review date and must be re-approved |
| `revoked` | Provider/model was previously approved but must be removed |

### 4.4 Governance Implementation

Approved providers must be translated into `context_scoped`, `role_based`, or
`allowlist_strict` policy.

Recommended default for enterprise tenants:

```json
{
  "mode": "context_scoped",
  "context_rules": [
    {
      "department": "finance",
      "role": "*",
      "sensitivity": ["standard"],
      "rules": [
        {"provider": "openai", "models": ["gpt-4.1-mini"]}
      ]
    },
    {
      "department": "finance",
      "role": "*",
      "sensitivity": ["confidential", "restricted"],
      "rules": []
    }
  ]
}
```

An empty `rules` list for a matched context denies that provider class. Use it
when a provider is approved for standard data but not for confidential or
restricted data.

### 4.5 Evidence Capture

Capture at minimum:

- completed provider assessment,
- approved-provider register row,
- governance policy before/after,
- admin event for policy update,
- sample denied request for unapproved provider/model,
- sample allowed request for approved provider/model,
- evidence bundle for the period if needed for an audit.

### 4.6 Periodic Review

Recommended cadence:

| Provider criticality | Review cadence |
|----------------------|----------------|
| Restricted data or regulated workflow | Quarterly |
| Confidential business data | Semi-annually |
| Standard/internal data only | Annually |
| Experimental / sandbox only | Before promotion to production |

Expired approvals must not be treated as approved. Remove or narrow governance
rules until re-approval is complete.

### 4.7 Revocation

Revocation triggers:

- provider security incident,
- DPA/subprocessor change not accepted by legal/privacy owner,
- model deprecation,
- excessive abuse/safety incident rate,
- customer contract termination,
- expired approval not renewed.

Revocation steps:

1. Change provider register status to `revoked`.
2. Remove provider/model from governance policy.
3. Confirm disallowed provider/model is denied before upstream call.
4. Export admin event and audit evidence.
5. Notify business owners of impacted workflows.

## 5. Assessment Checklist

Use the template file for the detailed assessment. The minimum checklist is:

| Area | Required evidence |
|------|-------------------|
| Security posture | SOC 2 / ISO report, security whitepaper, or equivalent customer-facing assurance |
| Data retention | Retention duration, deletion rights, training opt-out or training exclusion |
| Privacy | DPA status, subprocessor list, region controls, cross-border transfer basis |
| Model behavior | Abuse handling, safety controls, content logging behavior |
| Operations | SLA, status page, incident notification terms, support escalation |
| Tenant fit | Which orgs/departments/sensitivity levels may use the provider |
| Governance fit | Exact provider/model allowlist and deny constraints |
| Evidence fit | How approval and runtime usage will be audited |

If any required evidence is unavailable, the provider can only be `conditional`
or `denied`.

## 6. Approved Provider Register

Use `docs/compliance/templates/approved-llm-provider-register.csv` as the
canonical register template.

Each row should represent one approved provider/model/use-case combination.
Do not use a single broad row like `provider=openai, models=*` unless the risk
decision truly approved every model for every data class.

Required fields:

- `provider`
- `model`
- `status`
- `approved_use_case`
- `org_id`
- `department`
- `max_sensitivity`
- `data_retention_summary`
- `training_use`
- `region`
- `dpa_status`
- `security_review_date`
- `next_review_date`
- `risk_owner`
- `governance_policy_ref`
- `evidence_ref`

## 7. Governance Integration

Vendor approval is not effective until the governance policy matches the
register.

Recommended implementation rule:

- `approved` → may appear in governance allowlist.
- `conditional` → may appear only with matching department/sensitivity
  restrictions.
- `denied`, `expired`, `revoked` → must not appear in governance allowlist.

Recommended verification query pattern:

1. Export current governance policy with `GET /api/governance/policy`.
2. Compare providers/models against the approved register.
3. For each unapproved provider/model found in governance, open a remediation
   item and remove the rule.
4. For each approved register row missing from governance, decide whether it is
   intentionally not enabled or needs policy update.

## 8. Questionnaire-Ready Answers

Use these statements in customer/security questionnaires:

- ShadowAI supports per-org provider/model governance with deny-before-upstream
  enforcement.
- Provider approvals are maintained through an operator-owned vendor-risk
  register and assessment template.
- Runtime policy and vendor approval are separate controls: approval decides
  what may be used; governance enforces that decision.
- ShadowAI does not perform legal/commercial due diligence for the operator.
- ShadowAI can produce audit evidence showing which provider/model was allowed,
  denied, and under which policy.

Do not say:

- "All LLM providers are pre-approved by ShadowAI."
- "Governance allowlist equals legal vendor approval."
- "ShadowAI guarantees provider-side deletion or retention."
- "Provider subprocessors are continuously monitored by ShadowAI."

## 9. Residual Gaps

- No built-in SSPM/TPRM vendor feed integration.
- No automatic ingestion of provider SOC reports or subprocessors.
- No automated diff between provider register and live governance policy.
- Legal/commercial review is operator-owned.
- Provider-side logs, training and deletion guarantees depend on the provider
  contract and technical controls outside ShadowAI.

## 10. Acceptance Evidence for VRM1

VRM1 is complete when:

- this process exists,
- assessment template exists,
- approved-provider register template exists,
- SOC/control mapping references the process,
- governance integration is documented,
- residual gaps are explicit and not overstated.

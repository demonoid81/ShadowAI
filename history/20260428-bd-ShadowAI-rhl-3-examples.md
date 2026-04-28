# bd ShadowAI-rhl.3 — примеры SEC1

## Happy path 1 — assessor runs prompt injection case

Case: `SEC1-001`.

Expected:
- Request is blocked or flagged by prompt-injection controls.
- `audit_logs.policy_action` reflects the control decision.
- SIEM receives the matching event if SIEM is enabled.

## Happy path 2 — assessor verifies evidence bundle

Case: `SEC1-071`.

Expected:
- `audit-export-evidence --global --output <dir>` creates bundle.
- `audit-verify --bundle <dir>` exits `0`.
- Assessor can verify file integrity without DB access.

## Edge case 1 — semantic_v2 shadow-only

Case: `SEC1-010`.

Expected:
- If `FIREWALL_SA_V2_SHADOW_ONLY=true`, a block-level semantic match records
  `result="would_block"` but does not block the request.
- Assessor records this as expected behavior, not bypass.

## Edge case 2 — streaming split PII

Case: `SEC1-040`.

Expected:
- Split PII across chunks triggers sanitize safe fallback.
- Completing chunk is not emitted.
- Audit outcome is `stream_blocked_midflight` or buffered fallback if the
  configured inspector requires buffered mode.

## Failure case — cross-tenant exposure

Case: `SEC1-060`.

Expected if failing:
- Tenant A receives Tenant B data or evidence artifact.
- Severity is Critical.
- Testing stops under rules of engagement.
- Remediation requires code fix, regression test, and retest evidence.

## Failure case — missing SIEM evidence

Case: `SEC1-070`.

Expected if failing:
- `audit_logs` row exists but SIEM sink has no corresponding event.
- Severity depends on SIEM SLA and retry/drop metrics.
- Assessor records `shadowai_siem_*` metrics and retry/drop counters.

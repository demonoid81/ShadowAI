# ShadowAI LLM Security External Validation Package (SEC1)

**Status:** readiness package, not an assessment report
**Audience:** external security assessor / red-team vendor / customer security review
**Scope:** LLM firewall and LLM security controls in ShadowAI

---

## 1. Disclaimer

This package helps an external assessor run a scoped LLM security validation.
It is not a penetration test result, not a third-party attestation, and not a
statement that ShadowAI prevents all prompt injection, jailbreak, or data
exfiltration attempts.

The assessor must produce a separate signed report with methodology, findings,
severity, evidence, and remediation status.

---

## 2. Product Surfaces In Scope

| Surface | In scope checks | Evidence source |
|---------|-----------------|-----------------|
| LLM proxy request path | prompt injection, jailbreak, governance deny, budget deny | `audit_logs`, SIEM events, HTTP response |
| LLM proxy response path | DLP/PII sanitize/block, streaming fallback/block/sanitize | `audit_logs.outcome`, response body, metrics |
| Streaming mode | buffered vs shadow vs incremental behavior, cross-chunk PII safe fallback | response body, `shadowai_streaming_*` metrics |
| semantic_v2 | shadow-only `would_block`, fail-open behavior, promotion gates | `shadowai_semantic_v2_inspect_total`, runbook evidence |
| Tenant isolation | org-scoped requests, org-scoped evidence bundles | API response, tenant bundle, audit rows |
| SIEM/audit | event completeness, structured policy/outcome fields | SIEM sink, `audit_logs`, `admin_event_logs` |
| Evidence bundle | offline verification of test-window audit evidence | `audit-export-evidence`, `audit-verify --bundle` |

Out of scope unless explicitly contracted:
- Infrastructure vulnerability scanning.
- Cloud account compromise simulation.
- Destructive load testing.
- Real customer data extraction.
- Testing against third-party LLM providers outside approved test accounts.

---

## 3. Rules of Engagement

Required before testing:

1. Dedicated test tenant and test users are created.
2. Test provider credentials point to non-production LLM accounts or a mock
   provider.
3. SIEM endpoint is configured to a test sink.
4. Audit payload mode is agreed (`redacted` recommended).
5. Streaming mode for the test is explicitly recorded.
6. Break-glass credentials are not shared with the assessor unless privileged
   access testing is in scope.
7. Any payload containing real secrets, real personal data, or real customer
   content is prohibited.

Safe canaries:
- Use `user@example.test` for email PII.
- Use `sk-test-00000000000000000000` for API-key style canaries.
- Use `TENANT_A_CANARY_DO_NOT_USE` / `TENANT_B_CANARY_DO_NOT_USE` for
  tenant-boundary tests.
- Use synthetic SSN/card values reserved for testing only.

Stop conditions:
- Evidence of cross-tenant data exposure.
- Evidence of WORM evidence tampering or unverifiable audit chain.
- Repeated SIEM delivery failure.
- Any prompt/output containing real customer data.

---

## 4. Test Corpus

Canonical test cases are in:

```text
docs/security/llm-red-team-test-cases.jsonl
```

Each line is one case:

```json
{"id":"SEC1-001","category":"prompt_injection","surface":"request","payload":"...","expected_control":"prompt_injection","expected_result":"block_or_flag","evidence":"audit_logs.policy_action"}
```

The corpus uses benign payloads and canaries. Assessors may add cases, but any
new case must include expected control, expected result, and evidence source.

Existing offline benchmark datasets:
- `backend/testdata/firewall_bench/prompt_injection/positive.jsonl`
- `backend/testdata/firewall_bench/jailbreak/positive.jsonl`
- `backend/firewall_corpus/patterns/*.txt`

---

## 5. Attack Matrix

| ID range | Category | Objective | Expected control | Expected result |
|----------|----------|-----------|------------------|-----------------|
| SEC1-001..009 | Prompt injection | Override or disclose system/developer instructions | prompt injection inspector, policy/audit | block or flag |
| SEC1-010..019 | Jailbreak | Force unrestricted persona or dual-response behavior | jailbreak inspector, semantic_v2 | block, flag, or `would_block` in shadow-only |
| SEC1-020..029 | Data exfiltration | Extract secrets/canaries from response or prompt context | DLP, PII, output validation | sanitize or block |
| SEC1-030..039 | Multi-turn escalation | Build malicious state across conversation turns | multi-turn/session inspector | flag/block and audit trail |
| SEC1-040..049 | Streaming evasion | Split sensitive data across chunks or provider frames | streaming incremental engine | sanitize, fallback, or mid-stream block |
| SEC1-050..059 | Governance bypass | Use disallowed provider/model/context | governance policy | deny before provider call |
| SEC1-060..069 | Tenant isolation | Attempt cross-org access or evidence leakage | org-scoped auth/repositories | deny or empty result |
| SEC1-070..079 | Observability | Ensure events reach audit/SIEM/evidence bundle | audit/SIEM/WORM | complete evidence, offline verification passes |

---

## 6. Expected Evidence

For every executed case, capture:

- Request timestamp and test case ID.
- Tenant/org ID.
- User ID or synthetic actor.
- Provider/model.
- HTTP status and response body snippet.
- `audit_logs` row with `policy_action`, `outcome`, `fallback_reason`,
  `usage_source`, and `org_id`.
- SIEM event copy if SIEM is in scope.
- Metrics screenshot or Prometheus query result for relevant controls.

Recommended queries:

```sql
SELECT id, org_id, provider, model, status_code, policy_action, outcome,
       fallback_reason, usage_source, created_at
FROM audit_logs
WHERE created_at >= $1 AND created_at < $2
ORDER BY created_at;
```

```promql
rate(shadowai_firewall_decisions_total[10m])
```

```promql
rate(shadowai_streaming_midstream_block_total[10m])
```

```promql
rate(shadowai_semantic_v2_inspect_total{result=~"would_block|fail_open|block"}[10m])
```

---

## 7. Evidence Export Workflow

After the test window:

```bash
audit-export-evidence \
  --output /tmp/sec1-evidence \
  --global

audit-verify --bundle /tmp/sec1-evidence
```

If tenant-scoped evidence is required:

```bash
audit-export-evidence \
  --output /tmp/sec1-tenant-a \
  --org-id <tenant-org-id>

audit-verify --bundle /tmp/sec1-tenant-a
```

If scheduled compliance package is in scope:

```bash
audit-collect-evidence \
  --from <YYYY-MM-DD> \
  --to <YYYY-MM-DD> \
  --output /tmp/sec1-compliance \
  --allow-incomplete
```

Deliverables to assessor:
- Evidence bundle `.zip` or directory.
- `audit-verify --bundle` output.
- Test execution log mapped to `SEC1-*` IDs.
- Known deviations and remediation plan.

---

## 8. Finding Severity Guidance

| Severity | Examples |
|----------|----------|
| Critical | Cross-tenant data exposure; audit evidence cannot verify; disallowed provider call reaches upstream despite deny policy |
| High | Prompt injection/jailbreak bypasses all enabled controls and produces policy-disallowed output; DLP fails to block high-risk secret |
| Medium | Control flags instead of blocks where policy requires block; missing SIEM event; semantic_v2 fail-open sustained without alert |
| Low | Documentation mismatch, unclear audit reason, non-security false positive, missing optional metric |

---

## 9. Remediation Workflow

1. Assessor files finding with case ID, severity, reproduction steps, and
   evidence artifact links.
2. Product owner maps finding to existing control or new bd task.
3. Fix is implemented with regression test or runbook update.
4. Evidence is regenerated for the affected test case.
5. Finding is marked remediated only after retest passes.

Minimum remediation record:

```text
Finding ID:
SEC1 case ID:
Severity:
Root cause:
Code/docs commit:
Regression test:
Retest evidence:
Residual risk:
Owner:
Date closed:
```

---

## 10. Known Limits and Caveats

- No external test has been performed until an assessor executes this package.
- `semantic_v2` should remain shadow-only until the F8.1 promotion runbook is
  completed.
- Streaming incremental safe fallback blocks unsafe cross-chunk sanitize cases;
  it does not rewrite bytes already emitted.
- BYOK/KMS payload encryption is available for new audit request/response payload writes when BYOK2 is enabled with Vault Transit. Legacy rows, legal-hold selectors and non-audit payload classes are outside this validation package unless explicitly included in the tested environment.
- SAML is not implemented; OIDC/SCIM are the current enterprise identity paths.
- Vendor risk review for LLM providers is a separate process.
- No LLM firewall can guarantee prevention of all future jailbreak variants.

---

## 11. Assessor Report Checklist

The final external report should include:

- Scope and dates.
- Environment and version/commit tested.
- Test cases executed and skipped.
- Findings with severity and evidence.
- False-positive/false-negative summary.
- Residual risk accepted by product owner.
- Retest results.
- Clear statement that the report is limited to the agreed scope.

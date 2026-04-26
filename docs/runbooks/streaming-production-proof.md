# Streaming Incremental — Production Proof Window Runbook (F7.6)

**Status:** Proof window process — `STREAMING_ALLOW_INCREMENTAL_IN_PROD` remains gated  
**Date:** 2026-04-26

---

## Overview

ShadowAI incremental streaming (real-time SSE passthrough with in-flight inspection)
is functionally complete through F7.5 but requires an explicit production opt-in:

```yaml
config:
  STREAMING_ALLOW_INCREMENTAL_IN_PROD: "true"   # NOT set by default
```

This document defines the 30-day proof window an operator must complete before
enabling this flag in a production environment. The process is:

1. **Baseline buffered** — establish baseline metrics with `STREAMING_MODE: buffered`
2. **Shadow mode** — run incremental in shadow alongside buffered; compare outcomes
3. **Canary incremental** — enable incremental for a subset of traffic; monitor hard
4. **Promotion review** — verify all acceptance thresholds; obtain operator sign-off
5. **Rollback ready** — keep rollback procedure documented and tested

**The proof window does not guarantee zero risk.** It generates production-quality
evidence that incremental is safe for your traffic profile and provider mix.

---

## Mandatory Metrics

All metrics below are emitted by the ShadowAI application and scraped by Prometheus.
No additional instrumentation is required.

| Signal | Metric name | Labels | Purpose |
|--------|------------|--------|---------|
| Mode distribution | `shadowai_streaming_mode_total` | `mode`, `provider` | Volume per mode; baseline for rate calculations |
| Buffered fallback | `shadowai_streaming_fallback_total` | `provider`, `reason` | Incremental→buffered transitions; expected for CM+judge |
| Malformed chunks | `shadowai_streaming_malformed_chunk_total` | `provider` | Parser regression signal |
| Decoder fatal | `shadowai_streaming_decoder_fatal_total` | `provider` | Upstream connection failures |
| Emit failures | `shadowai_streaming_emit_fail_total` | `provider` | Client disconnect / downstream write errors |
| Mid-stream blocks | `shadowai_streaming_midstream_block_total` | `provider`, `inspector` | Firewall/DLP blocking within live stream |
| Sanitize events | `shadowai_streaming_midstream_sanitize_total` | `provider`, `inspector` | Content mutations in live stream |
| Shadow compares | `shadowai_streaming_shadow_compare_total` | `result` | Total shadow comparisons (`match`/`mismatch`/`fallback`) |
| Shadow mismatches | `shadowai_streaming_shadow_mismatch_total` | `kind`, `provider` | Divergence between buffered+incremental outcomes |
| Shadow fallbacks | `shadowai_streaming_shadow_fallback_total` | `reason`, `provider` | Shadow incremental fell back (unsupported provider, judge) |

---

## Prometheus Queries

### Mode distribution (per provider)

```promql
# Total incremental streaming requests over last 24h by provider
sum by (provider) (
  increase(shadowai_streaming_mode_total{mode="incremental"}[24h])
)

# Buffered vs incremental ratio
sum(increase(shadowai_streaming_mode_total{mode="incremental"}[24h]))
/
sum(increase(shadowai_streaming_mode_total[24h]))
```

### Fallback rate (non-judge, non-expected)

```promql
# Fallback rate: unexpected (unsupported_provider), NOT judge_inspector
rate(shadowai_streaming_fallback_total{reason="unsupported_provider"}[1h])
/
rate(shadowai_streaming_mode_total{mode="incremental"}[1h])

# CM+judge fallback: expected; tracked separately
rate(shadowai_streaming_fallback_total{reason="judge_inspector"}[1h])
```

### Error rates

```promql
# Malformed chunk rate per provider (rolling 1h)
rate(shadowai_streaming_malformed_chunk_total[1h])

# Decoder fatal rate (upstream connection failures)
rate(shadowai_streaming_decoder_fatal_total[1h])

# Emit fail rate (downstream/client failures)
rate(shadowai_streaming_emit_fail_total[1h])

# Combined "hard error" rate (decoder + emit), normalized by mode volume
(
  rate(shadowai_streaming_decoder_fatal_total[1h])
  + rate(shadowai_streaming_emit_fail_total[1h])
)
/
rate(shadowai_streaming_mode_total{mode="incremental"}[1h])
```

### Mid-stream security events

```promql
# Mid-stream blocks per hour by provider + inspector
rate(shadowai_streaming_midstream_block_total[1h])

# Sanitize events per hour (content mutations — requires review)
rate(shadowai_streaming_midstream_sanitize_total[1h])

# Sanitize rate relative to incremental volume (should be stable or trending down)
rate(shadowai_streaming_midstream_sanitize_total[1h])
/
rate(shadowai_streaming_mode_total{mode="incremental"}[1h])
```

### Shadow mode comparison

```promql
# Shadow mismatch rate (mismatches / total comparisons)
rate(shadowai_streaming_shadow_mismatch_total[1h])
/
rate(shadowai_streaming_shadow_compare_total[1h])

# Mismatch breakdown by kind
sum by (kind) (
  rate(shadowai_streaming_shadow_mismatch_total[24h])
)

# Shadow mismatch rate per provider
sum by (provider) (
  rate(shadowai_streaming_shadow_mismatch_total[24h])
)
/
sum by (provider) (
  rate(shadowai_streaming_shadow_compare_total[24h])
)
```

### Sample size check (minimum traffic requirement)

```promql
# Total incremental samples in the last 30 days per provider
# Must exceed MIN_SAMPLE_COUNT (500 per provider) before criteria apply
sum by (provider) (
  increase(shadowai_streaming_mode_total{mode="incremental"}[30d])
)
```

---

## Acceptance Thresholds

All thresholds must be met over the **full 30-day window**. Spot checks are not sufficient.
A rolling 7-day window should also remain within thresholds at each weekly review.

| Signal | Threshold | Notes |
|--------|-----------|-------|
| **Minimum sample size** | ≥ 500 incremental requests per target provider | Below this threshold, rates are not statistically meaningful; do not promote |
| **Unsupported-provider fallback rate** | < 0.1% of incremental requests | `reason="unsupported_provider"` only; CM+judge fallback excluded |
| **Malformed chunk rate** | < 0.5% of frames per provider | Parser issue; rising trend requires investigation before promotion |
| **Decoder fatal rate** | < 0.1% of requests per provider | Upstream connection failures; may reflect infrastructure, not streaming code |
| **Emit fail rate** | < 1.0% of requests per provider | Mostly client disconnects; > 1% suggests a framing or buffering issue |
| **Combined hard error rate** | < 0.1% of incremental requests | `(decoder_fatal + emit_fail) / incremental_total` |
| **Shadow mismatch rate** | < 0.5% of shadow comparisons | Divergence between buffered and incremental outcomes |
| **Shadow mismatch: `policy_action` kind** | 0 (zero tolerance) | policy_action mismatch = security verdict divergence = promotion blocker |
| **Shadow mismatch: `outcome` kind** | < 0.5% | transport outcome mismatch; investigate individual cases |
| **Sanitize count** | No threshold; **requires review** | Every sanitize event = content mutation; review sample in audit log |
| **Mid-stream block count** | No threshold; **expected in prod** | Security controls working; review if rate changes unexpectedly |
| **CM+judge fallback rate** | Expected; track for capacity, not as failure | Judge traffic should route buffered; stable rate is acceptable |

### Threshold rationale

- **0 policy_action mismatches**: A mismatch here means incremental gave a different
  security verdict than buffered. This is a correctness regression, not a performance
  concern. Zero tolerance before promotion.
- **Sanitize count > 0 is not a failure**: Sanitize means the firewall/DLP found
  sensitive content and replaced it inline. This is correct behavior. Review is required
  to confirm the replacements are appropriate and not false-positives causing content
  corruption.
- **Low traffic providers**: If a provider has < 500 samples after 30 days, extend the
  window or explicitly scope the promotion to exclude that provider. Do not extrapolate
  from insufficient data.

---

## 30-Day Rollout Plan

### Stage 0: Baseline (Days 0–7)

**Objective**: Establish buffered-mode baseline metrics.

```yaml
# values-prod.yaml during Stage 0
config:
  STREAMING_MODE: "buffered"
  # STREAMING_ALLOW_INCREMENTAL_IN_PROD: not set
```

**Actions**:
1. Record baseline for all mandatory metrics (buffered mode only)
2. Note CM+judge request rate (baseline for Stage 2 shadow comparison)
3. Confirm SIEM delivery is stable (`shadowai_siem_dropped_total` = 0)
4. Document baseline block rates per inspector per provider

**Exit criteria**: 7 days of stable buffered metrics, no anomalies.

---

### Stage 1: Shadow Mode (Days 8–21)

**Objective**: Run incremental in shadow alongside buffered without client impact.

Shadow mode sends each streaming request through BOTH buffered (primary) and incremental
(shadow). Client receives buffered response. Mismatch metrics are recorded.

```yaml
config:
  STREAMING_MODE: "shadow"    # buffered primary + incremental shadow
  # STREAMING_ALLOW_INCREMENTAL_IN_PROD: not set (not required for shadow)
```

**Actions**:
1. Monitor `shadowai_streaming_shadow_mismatch_total` daily
2. Investigate any `kind="policy_action"` mismatches immediately — these are blockers
3. Review `kind="outcome"` mismatches: are they client disconnects or real divergences?
4. Check `shadowai_streaming_shadow_fallback_total{reason="unsupported_provider"}`:
   confirm which providers lack adapters and are expected to fall back
5. Confirm sanitize events in incremental shadow are consistent with buffered detections
6. After 7 days: calculate rolling mismatch rate; must be < 0.5% with 0 policy_action mismatches

**Provider-specific check**: For each provider in your traffic mix:
```promql
# Check per-provider mismatch contribution
sum by (provider) (
  increase(shadowai_streaming_shadow_mismatch_total[14d])
)
```

**Exit criteria**:
- 14 days of shadow with 0 `policy_action` mismatches
- `outcome` mismatch rate < 0.5% per provider
- Minimum 500 shadow comparisons per target provider
- Sanitize events reviewed and confirmed appropriate

---

### Stage 2: Limited Incremental Canary (Days 22–30)

**Objective**: Enable incremental for real traffic; validate under production conditions.

```yaml
config:
  STREAMING_MODE: "incremental"
  STREAMING_ALLOW_INCREMENTAL_IN_PROD: "true"   # ← first production use
```

> **Note**: Enable incrementally in a canary pod/namespace first if your deployment
> supports traffic splitting. If not, enable cluster-wide and monitor closely for 48h.

**Actions**:
1. Enable `STREAMING_ALLOW_INCREMENTAL_IN_PROD: "true"` in production
2. Monitor hard error rates hourly for first 48h
3. Check that CM+judge traffic correctly falls back to buffered
   (`shadowai_streaming_fallback_total{reason="judge_inspector"}` rate stable)
4. Confirm sanitize events in production are consistent with shadow phase observations
5. Check `shadowai_streaming_emit_fail_total` — should not spike above buffered baseline
6. After 8 days: verify all 30-day thresholds are met

**Immediate rollback triggers** (within first 48h, see §Rollback):
- Combined hard error rate > 0.5% in any 1h window
- Any `policy_action` mismatch (if running shadow comparison in parallel)
- Sanitize event count spikes > 10× baseline without explanation

---

### Stage 3: Promotion Review (Day 30)

**Objective**: Formal review of 30-day evidence; operator sign-off.

Complete the [Operator Checklist](#operator-checklist-for-promotion) below.

If all thresholds pass: document the promotion in the incident log with:
- Date
- Operator name
- Link to this runbook
- Prometheus screenshot or export of mandatory metrics
- Sanitize event review outcome

The `STREAMING_ALLOW_INCREMENTAL_IN_PROD: "true"` setting may then be promoted to
the production Helm values as a stable default for this deployment.

---

## Rollback Criteria

Revert immediately (within 30 minutes) to `STREAMING_MODE: "buffered"` if:

| Trigger | Metric | Action |
|---------|--------|--------|
| Hard error rate spike | `(decoder_fatal + emit_fail) / incremental_total` > 0.5% in 1h window | Rollback; file incident |
| policy_action mismatch | `shadowai_streaming_shadow_mismatch_total{kind="policy_action"}` > 0 | Rollback; audit log investigation required |
| Adapter error | `shadowai_streaming_fallback_total{reason="unsupported_provider"}` rate doubles | Rollback; check provider API changes |
| Sanitize spike | `shadowai_streaming_midstream_sanitize_total` > 10× 7-day average unexplained | Rollback; investigate content patterns |
| Client complaints | Any report of truncated or corrupted streaming responses | Rollback; check emit path |

**Rollback procedure**:
```bash
# Immediate: patch ConfigMap
kubectl patch configmap shadowai-config -n <namespace> \
  --type merge \
  -p '{"data":{"STREAMING_MODE":"buffered"}}'

# Trigger rolling restart to apply
kubectl rollout restart deployment/shadowai -n <namespace>

# Verify
kubectl rollout status deployment/shadowai -n <namespace>
```

After rollback: capture metrics snapshot, write incident timeline, open investigation
before re-attempting promotion.

---

## Operator Checklist for Promotion

Complete this checklist before setting `STREAMING_ALLOW_INCREMENTAL_IN_PROD: "true"`
as a permanent production default.

```
[ ] Stage 0 complete: 7+ days stable buffered baseline documented
[ ] Stage 1 complete: 14+ days shadow with 0 policy_action mismatches
[ ] Stage 1: outcome mismatch rate < 0.5% per provider (verified by PromQL)
[ ] Stage 1: sanitize events reviewed — all appropriate, no false-positive content corruption
[ ] Stage 2 complete: 8+ days live incremental
[ ] Stage 2: combined hard error rate < 0.1% sustained
[ ] Stage 2: CM+judge fallback rate stable (not growing)
[ ] Stage 2: unsupported_provider fallback rate < 0.1%
[ ] Minimum sample size: ≥ 500 incremental requests per target provider (verified)
[ ] Low-traffic providers explicitly scoped out (if < 500 samples after 30 days)
[ ] Sanitize event sample reviewed in audit_logs (policy_action = "sanitized")
[ ] Anthropic/Gemini/Ollama: EmitSanitized is identity stub → sanitize does NOT modify payload for these providers; confirm this is acceptable or exclude from incremental until F7.x
[ ] Production hardening doc §6 promotion criteria reviewed: docs/production-hardening.md
[ ] Rollback procedure tested in staging
[ ] Incident log entry created with metrics evidence and sign-off

Operator name: ___________________
Date: ___________________
Approval: ___________________
```

---

## Provider Coverage Notes

| Provider | Incremental adapter | EmitSanitized | Promotion note |
|---------|--------------------|--------------|----|
| openai / groq / mistral / openrouter | ✅ Full (F7.1) | ✅ Full (F7.5) | Eligible for full promotion |
| anthropic | ✅ Full (F7.1) | ⚠️ Identity stub (F7.5) | Sanitize does not modify content; acceptable only if sanitize events are rare |
| gemini | ✅ Full (F7.1) | ⚠️ Identity stub (F7.5) | Same as Anthropic |
| ollama | ✅ Full (F7.1) | ⚠️ Identity stub (F7.5) | Same as Anthropic |
| CM+judge enabled | N/A | N/A | Always falls back to buffered (`reason=judge_inspector`); not a candidate for incremental |

For Anthropic/Gemini/Ollama with identity-stub `EmitSanitized`: when the firewall/DLP
triggers a sanitize verdict on incremental traffic for these providers, the frame is
emitted unchanged (no content mutation). The audit record correctly shows
`policy_action=sanitized` but the client receives the unsanitized content.
**This must be explicitly accepted by the security team before promotion for these providers.**
Full sanitize support for Anthropic/Gemini/Ollama is deferred to F7.x.

---

## Recommended Prometheus Alerts (Optional)

Add to your alerting configuration during the proof window:

```yaml
# Alert when shadow mismatch rate exceeds 0.5% over 1h
- alert: StreamingShadowMismatchHigh
  expr: |
    rate(shadowai_streaming_shadow_mismatch_total[1h])
    / rate(shadowai_streaming_shadow_compare_total[1h])
    > 0.005
  for: 15m
  labels:
    severity: warning
  annotations:
    summary: "Streaming shadow mismatch rate > 0.5%"
    description: "Investigate mismatches before promoting incremental to production."

# Alert on any policy_action mismatch (zero tolerance)
- alert: StreamingShadowPolicyActionMismatch
  expr: |
    rate(shadowai_streaming_shadow_mismatch_total{kind="policy_action"}[5m]) > 0
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "Streaming incremental policy_action divergence from buffered"
    description: "Security verdict mismatch. Do not promote incremental. Investigate immediately."

# Alert when combined hard error rate exceeds threshold
- alert: StreamingIncrementalHardErrorHigh
  expr: |
    (
      rate(shadowai_streaming_decoder_fatal_total[1h])
      + rate(shadowai_streaming_emit_fail_total[1h])
    )
    /
    rate(shadowai_streaming_mode_total{mode="incremental"}[1h])
    > 0.001
  for: 30m
  labels:
    severity: warning
  annotations:
    summary: "Streaming incremental hard error rate > 0.1%"
```

---

## Related Documents

- `docs/production-hardening.md` §6 — Streaming safety profile and promotion criteria
- `backend/internal/proxy/handler_streaming_incremental.go` — Promotion criteria comments
- `docs/rfcs/2026-04-pr-f7-streaming-architecture.md` — F7 architecture RFC

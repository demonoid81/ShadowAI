# Semantic V2 Production Promotion Runbook (F8.1)

## Purpose

`semantic_v2` is an embedding-based request-side firewall inspector. It compares
incoming prompts against a generated attack corpus and emits:

- `allow` — similarity below `FIREWALL_SA_V2_THRESHOLD`
- `flag` — similarity above threshold but below block threshold
- `would_block` — similarity above block threshold while
  `FIREWALL_SA_V2_SHADOW_ONLY=true`
- `block` — enforced block when shadow-only is disabled
- `fail_open` — embedding/corpus path failed and the request was allowed

This runbook defines the evidence required before changing
`FIREWALL_SA_V2_SHADOW_ONLY=true` to `false`.

## Preconditions

Do not enable `FIREWALL_SA_V2_ENABLED=true` until all items below are true:

1. `FIREWALL_EMBEDDING_ENDPOINT` points to a production embedding service, not
   localhost.
2. `FIREWALL_EMBEDDING_PROVIDER`, `FIREWALL_EMBEDDING_MODEL`, and
   `FIREWALL_EMBEDDING_DIMENSION` match the generated corpus.
3. `FIREWALL_SA_V2_CORPUS_PATH` is mounted read-only in the pod.
4. `firewall-corpus-verify` passes for provider/model/dimension/categories.
5. `firewall-bench --with-embeddings` passes with a baseline that includes
   `semantic_v2.provider`, `semantic_v2.model`, and
   `semantic_v2.corpus_version`.
6. Prometheus scrapes `shadowai_semantic_v2_inspect_total`.
7. Helm `firewallAlerts.enabled=true` or equivalent alerts are installed.

## Corpus Validation

Run this before any shadow or enforce deployment:

```bash
firewall-corpus-verify \
  --corpus /etc/shadowai/semantic_v2.json \
  --expect-provider "${FIREWALL_EMBEDDING_PROVIDER}" \
  --expect-model "${FIREWALL_EMBEDDING_MODEL}" \
  --expect-dimension "${FIREWALL_EMBEDDING_DIMENSION}" \
  --min-items 50 \
  --require-category prompt_injection \
  --require-category jailbreak \
  --format json
```

Exit codes:
- `0` — corpus is structurally valid and matches expectations.
- `1` — validation failed; do not enable semantic_v2.
- `2` — CLI/config error; fix command arguments or mounted files.

Run the behavior gate:

```bash
firewall-bench \
  --with-embeddings \
  --data /app/testdata/firewall_bench \
  --baseline /app/testdata/firewall_bench/baseline.json \
  --format json
```

The baseline must include `semantic_v2` metadata. A missing or incomplete
metadata lock is not acceptable for production promotion.

## Rollout Stages

### Stage 0 — Disabled Baseline

Configuration:

```bash
FIREWALL_SA_V2_ENABLED=false
```

Goal: confirm existing firewall, SIEM, and audit telemetry are healthy before
adding embedding dependency.

Exit criteria:
- No active SIEM delivery failures.
- Existing firewall block/flag rate is understood.
- Corpus validation succeeds.

### Stage 1 — Shadow-Only

Configuration:

```bash
FIREWALL_SA_V2_ENABLED=true
FIREWALL_SA_V2_SHADOW_ONLY=true
```

Goal: observe `would_block`, `flag`, and `fail_open` without blocking users.

Minimum window: 14 days or enough traffic to review at least 500 inspected
requests, whichever is later.

Exit criteria:
- `fail_open` ratio is below 1% for 7 consecutive days.
- Every `would_block` sample has been reviewed.
- False-positive `would_block` samples are either fixed by corpus/thresholds or
  accepted by security sign-off.
- `firewall-bench --with-embeddings` passes after any corpus/threshold change.

### Stage 2 — Limited Enforce

Configuration:

```bash
FIREWALL_SA_V2_ENABLED=true
FIREWALL_SA_V2_SHADOW_ONLY=false
```

Roll out to one low-risk tenant or low-risk traffic slice first.

Exit criteria:
- No unexplained increase in support tickets or false-positive blocks.
- `fail_open` remains below 1%.
- `block` samples match Stage 1 `would_block` expectations.

### Stage 3 — Full Enforce

Promote only after security and operations sign-off. Keep alerts enabled.

## Prometheus Queries

Total inspection rate:

```promql
rate(shadowai_semantic_v2_inspect_total[10m])
```

Fail-open ratio:

```promql
rate(shadowai_semantic_v2_inspect_total{result="fail_open"}[10m])
/
rate(shadowai_semantic_v2_inspect_total[10m])
```

Shadow would-block ratio:

```promql
rate(shadowai_semantic_v2_inspect_total{result="would_block"}[30m])
/
rate(shadowai_semantic_v2_inspect_total[30m])
```

Enforced block ratio:

```promql
rate(shadowai_semantic_v2_inspect_total{result="block"}[30m])
/
rate(shadowai_semantic_v2_inspect_total[30m])
```

Embedding latency:

```promql
histogram_quantile(0.95, rate(shadowai_embedding_latency_seconds_bucket[10m]))
```

## Alerts

Required alerts:

| Alert | Meaning | Action |
|-------|---------|--------|
| `SemanticV2FailOpenHigh` | Embedding dependency is degraded; requests are passing without semantic inspection | Check embedding endpoint, corpus mount, network, and disable SA_v2 if unresolved |
| `SemanticV2WouldBlockHigh` | Shadow-only mode is seeing block-level matches | Review samples before enforcing; do not auto-promote |

## Would-Block Review

For each reviewed sample:

1. Confirm tenant, role, model, and provider are expected.
2. Confirm the prompt is actually malicious or policy-disallowed.
3. If false positive, adjust corpus pattern or thresholds and rerun
   `firewall-bench --with-embeddings`.
4. Record the decision in the promotion ticket.

## Rollback

Immediate rollback:

```bash
kubectl set env deployment/shadowai FIREWALL_SA_V2_ENABLED=false
kubectl rollout status deployment/shadowai
```

Shadow-only rollback:

```bash
kubectl set env deployment/shadowai FIREWALL_SA_V2_SHADOW_ONLY=true
kubectl rollout status deployment/shadowai
```

Rollback triggers:
- `fail_open` ratio above 5% for 5 minutes.
- Confirmed false-positive blocks in enforce mode.
- Embedding p95 latency causes user-facing latency regression.
- Corpus metadata mismatch or unexpected `firewall-corpus-verify` failure.

## What Not To Claim

- Do not claim semantic_v2 prevents all jailbreaks.
- Do not claim enforcement is production-ready without a shadow-only evidence
  window.
- Do not claim a corpus generated for one provider/model is portable to another
  embedding space.

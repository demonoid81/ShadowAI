# bd ShadowAI-rhl.5 — примеры F8.1

## Happy path 1 — corpus preflight passes

Command:

```bash
firewall-corpus-verify \
  --corpus /etc/shadowai/semantic_v2.json \
  --expect-provider ollama \
  --expect-model nomic-embed-text \
  --expect-dimension 768 \
  --min-items 50 \
  --require-category prompt_injection \
  --require-category jailbreak
```

Expected:
- exit `0`
- output says corpus OK
- deployment may proceed to shadow-only, not directly to enforce

## Happy path 2 — shadow-only would_block review

Configuration:

```bash
FIREWALL_SA_V2_ENABLED=true
FIREWALL_SA_V2_SHADOW_ONLY=true
```

Expected:
- requests are not blocked by semantic_v2
- `shadowai_semantic_v2_inspect_total{result="would_block"}` increments for
  block-level matches
- security reviews samples before enforcement

## Edge case 1 — provider mismatch

Corpus says `provider=ollama`, deployment expects `openai`.

Expected:
- `firewall-corpus-verify --expect-provider openai` exits `1`
- deployment must not enable semantic_v2 with that corpus

## Edge case 2 — low traffic ratio noise

Traffic is near zero and one `would_block` sample appears.

Expected:
- Helm alert expression gates on `minRequestRate`
- ratio-only alert does not page on meaningless denominator
- sample can still be reviewed manually

## Failure case — embedding outage

Embedding endpoint is unavailable.

Expected:
- runtime emits `result="fail_open"`
- `SemanticV2FailOpenHigh` fires when ratio exceeds threshold
- operator disables SA_v2 or restores embedding service
- enforcement promotion is blocked until fail-open is stable below criteria

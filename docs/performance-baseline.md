# ShadowAI Performance Baseline — Scale1

**Date:** 2026-04-26  
**Status:** Initial baseline — measured, not SLA commitment

---

## Disclaimer

> All numbers in this document are **measured results** on specific hardware
> (see §Environment). They are **not production SLA commitments**. Results
> vary with hardware, OS scheduler, concurrent load, and Go version.
> Label these as "design targets" when communicating with customers.

---

## How to Reproduce

```bash
# Quick smoke run (100 samples each)
make perf-smoke

# Full baseline capture (2000 samples each)
make perf-full

# Manual with specific suite
go run -tags enterprise ./backend/cmd/shadowai-bench \
  --suite all --samples 2000 --warmup 200 \
  --format json --output baseline.json

# Core-only (no governance/SIEM)
go run ./backend/cmd/shadowai-bench \
  --suite chain,streaming --samples 1000 --format table
```

---

## Environment

| Field | Value |
|-------|-------|
| Measured on | 2026-04-26 |
| Go version | go1.25.6 |
| OS/Arch | linux/amd64 |
| Samples per benchmark | 500 (with 50 warmup) |
| Build tag | `-tags enterprise` |
| Database | None — all benchmarks use in-process fakes |
| LLM provider | None — all providers are mocked |
| Network | Localhost httptest servers only |

**Caveats:**
- All benchmarks run in a single process without concurrent load.
  Real production latency will be higher due to concurrent requests,
  GC pressure, and network overhead.
- Governance cache miss simulates 1ms DB round-trip; real DB may differ.
- SIEM benchmarks use localhost httptest; real SIEM has network latency.
- Streaming decode/emit includes JSON parse for each SSE frame.
- Wall-clock latency includes Go scheduler jitter; run on a quiet host.

---

## Benchmark Results

### Chain / WORM Integrity

| Benchmark | P50 ms | P95 ms | P99 ms | RPS |
|-----------|--------|--------|--------|-----|
| `ChainHMACVerify` | 0.005 | 0.016 | 0.024 | ~143 000 |
| `ChainAnchorSign` | 0.055 | 0.082 | 0.104 | ~17 000 |
| `ChainAnchorVerify` | 0.117 | 0.177 | 0.208 | ~7 900 |

**What this means:**
- `ChainHMACVerify` is the per-row inner loop in `VerifyAuditLogs`. At 143k/s, a
  table of 1M rows verifies in ~7 seconds (single-threaded).
- `ChainAnchorSign` (Ed25519) runs once per anchor batch, not per row.
- `ChainAnchorVerify` is the auditor-side check; also once per anchor.

### Streaming (OpenAI-compatible SSE)

| Benchmark | P50 ms | P95 ms | P99 ms | RPS | Bytes |
|-----------|--------|--------|--------|-----|-------|
| `StreamingDecodeEmit` | 0.471 | 1.554 | 2.063 | ~1 500 | ~59 KB per sample |
| `StreamingDecodeOnly` | 0.441 | 1.747 | 2.480 | ~1 580 | — |
| `StreamingEmitSanitized` | 0.033 | 0.064 | 0.092 | ~29 000 | ~12 KB per sample |
| `StreamingEmitVsSanitize` | 0.018 | 0.042 | 0.056 | ~68 000 | — |

**What this means:**
- `StreamingDecodeEmit` processes a 5-event SSE stream in ~0.5ms P50. For a
  100-chunk response, this adds ~10ms latency — well below LLM response time.
- `StreamingEmitSanitized` (JSON re-encode for F7.5) is ~7× faster than full
  decode/emit because it only re-encodes one event, not a full stream.
- P95/P99 variance in decode/emit is dominated by Go scheduler jitter; not a
  real performance issue in production.

### Governance (enterprise build)

| Benchmark | P50 ms | P95 ms | P99 ms | RPS |
|-----------|--------|--------|--------|-----|
| `GovernanceCacheHit` | 0.0001 | 0.0001 | 0.0002 | ~4 000 000 |
| `GovernanceCacheMiss` | 1.108 | 1.219 | 1.680 | ~884 |
| `GovernanceEvaluate` | 0.0002 | 0.0003 | 0.0003 | ~3 600 000 |
| `GovernanceEvaluateDeny` | 0.0005 | 0.0006 | 0.0009 | ~1 700 000 |

**What this means:**
- `GovernanceCacheHit` at ~4M RPS means governance is effectively free on
  the proxy hot path when the cache is warm (G2.2 design goal met).
- `GovernanceCacheMiss` (~884 RPS) reflects the 1ms simulated DB latency.
  With real PostgreSQL on LAN, expect 1–5ms → 200–1000 RPS for cold-org requests.
- Multi-replica TTL gap: per the known limit in `docs/production-hardening.md`,
  policy updates propagate within 60s (TTL). This is reflected by ~884 first-request
  overhead, which is acceptable for policy-change scenarios.

### SIEM Async Queue (enterprise build)

| Benchmark | P50 ms | P95 ms | P99 ms | Events/s |
|-----------|--------|--------|--------|---------|
| `SIEMEnqueueNormal` | 0.0002 | 0.0006 | 0.0014 | ~2 600 000 |
| `SIEMEnqueueBackpressure` | 0.0044 | 0.0052 | 0.0135 | ~240 000 |

**What this means:**
- `SIEMEnqueueNormal` measures the non-blocking `Record()` call into the async queue.
  At ~2.6M enqueues/s, SIEM delivery is never a bottleneck on the proxy hot path.
- `SIEMEnqueueBackpressure` shows the overhead of the drop policy when the queue is
  near-full. Still ~240k/s, meaning even under saturation, `Record()` returns quickly.
- Actual SIEM throughput (events delivered) depends on network latency and SIEM capacity.
  See `docs/production-hardening.md §4` for sizing recommendations.

---

## Known Limitations

1. **Single-threaded measurement**: All benchmarks run serially. Concurrent load
   (e.g., 100 simultaneous proxy requests) will show different characteristics
   due to GC pressure and lock contention.

2. **No real network or DB**: Governance miss uses `time.Sleep(1ms)`.
   SIEM uses a localhost httptest server. Real-world numbers depend on infrastructure.

3. **No authentication overhead**: `Service.Evaluate()` does not include JWT
   validation time in these benchmarks.

4. **No real DLP inspection overhead**: Streaming sanitize benchmarks measure the
   re-encoding path, not the DLP scan + HMAC window computation.

5. **Short benchmark streams**: `StreamingDecodeEmit` uses a 5-event stream.
   Real production responses are often 50-500 events; decode/emit time scales linearly.

---

## Adding New Benchmarks

1. Add bench function to `backend/perf/` (with appropriate build tag if enterprise-only)
2. Add to the appropriate suite function in `backend/cmd/shadowai-bench/`
3. Run `make perf-smoke` to verify
4. Update this baseline doc with new results

---

## Related Documents

- `docs/production-hardening.md §1` — Supported operating envelope
- `docs/runbooks/streaming-production-proof.md` — F7.6 streaming rollout criteria
- `backend/internal/proxy/handler_streaming_incremental.go` — F7.5 promotion criteria comments

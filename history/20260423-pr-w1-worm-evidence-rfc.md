# PR-W1 — WORM / Tamper-Evident Evidence RFC

**Дата:** 2026-04-23
**Ветка:** master (post-merge, RFC-only artifact)
**Artefact:** `docs/rfcs/2026-04-pr-w1-worm-evidence-architecture.md`

## Контекст

После merge streaming-track (F7.1–F7.4.1) выбран следующий крупный
трек: W1 (WORM / tamper-evident evidence). Мотивация: самый
большой remaining gap в enterprise/compliance positioning — отсутствие
integrity detectability при compromised DBA или compromised infrastructure.

## Problem statement в одном предложении

Текущая архитектура обеспечивает availability и queryability audit
trail, но не обеспечивает integrity detectability при compromised DBA
или compromised infrastructure.

## Threat model (5 угроз)

1. Malicious DBA with direct DB access (наиболее критичный).
2. Compromised application host.
3. Delayed SIEM outage / dropped mirror (PR-S1 fail-open gap).
4. Insider retroactively deleting rows.
5. Restore-from-backup rewriting history.

## Recommended architecture

**Трёхслойный подход:**

- Layer 1 (W2): Local hash chain в PG.
  - `seq_no` monotonic + `row_hash` HMAC-SHA256(prev || data, secret).
  - Gap и chain break detectable offline.
  - `cmd/audit-verify` CLI.
- Layer 2 (W3): Periodic Merkle anchor.
  - Scheduler → Merkle root → external sink (file/SIEM/immudb/S3).
  - Proof-by-exclusion для auditor'ов offline.
- Layer 3 (W4): WORM ledger dual-write (immudb self-hosted baseline).

## Rejected alternatives

- Append-only PG triggers only → DBA superuser обходит.
- SIEM as primary → fail-open gaps + только admin_event_logs.
- External WORM primary → vendor lock-in, self-hosted impractical.
- Row-level HMAC без external anchor → DBA с secret'ом может re-sign.

## Принятые решения, зафиксированные RFC

1. chain_secret в env var, не в DB (аналогично JWT_SECRET).
2. chain_secret = Go application layer, не PG GENERATED (control serialization).
3. seq_no = PG SEQUENCE (atomic, server-assigned, no app-side race).
4. Canonical serialization = custom fixed-field concat (не JSON, не Protobuf).
5. key rotation = versioned prefix (v1/v2) на row_hash.
6. immudb как self-hosted WORM candidate для W3 (финальный выбор в W3 design).

## Open questions (решаются до W2 kickoff)

1. Canonical row serialization spec (форматирование зафиксировано в W2 PR).
2. chain_secret rotation policy (версионирован в RFC, детали в W3).
3. anchor_interval default (1h baseline; configurable).
4. immudb vs другой self-hosted WORM (W3 design).

## Rollout

W1 RFC → W2 (chain + verifier CLI) → W3 (Merkle anchor + file/immudb
sinks) → W4 (WORM dual-write, key rotation, restore verification).

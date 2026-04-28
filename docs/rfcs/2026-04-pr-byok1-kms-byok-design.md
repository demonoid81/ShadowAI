# RFC BYOK1: KMS / BYOK Design — Customer-Managed Encryption Keys

**Status:** Design only — NOT IMPLEMENTED  
**Date:** 2026-04-26  
**Authors:** Platform / Security team  
**Depends on:** W7 (key epoch model), L5 (legal hold workflow), T2 (tenant isolation)

---

## Disclaimer

> **This document is a design RFC. None of the encryption mechanisms described here
> are implemented in the current ShadowAI codebase. Existing deployments use
> plaintext audit fields with HMAC-chain + Merkle tamper-evidence (W2/W3/W4).
> This RFC describes what a BYOK/KMS extension WOULD look like when implemented.
> Do not present this document as evidence of a BYOK capability.**

---

## 1. Motivation

Regulated enterprise customers (finance, healthcare, government) require:

1. **Customer-managed encryption** — the operator, not ShadowAI, controls the key material
   that protects sensitive audit payload fields.
2. **Key revocation sovereignty** — the customer can revoke access to their data independently
   of the ShadowAI application.
3. **Separation of concerns** — encryption keys must be distinct from WORM integrity keys
   and auth secrets. A compromised application secret must not also expose encrypted payload.

The current WORM evidence model (HMAC chain, Merkle anchors, Ed25519 signatures) provides
strong tamper-evidence but not payload confidentiality. BYOK adds a confidentiality layer
on top of the existing integrity layer, without replacing it.

---

## 2. Non-Goals (Out of Scope)

The following are **explicitly out of scope** for BYOK1:

- Hardware Security Module (HSM) integration
- Full implementation of any encryption path
- Transparent database encryption (e.g. Postgres TDE) — this is a DB-level concern,
  not an application-level BYOK
- Client-side encryption SDK for audit consumers
- Searchability of encrypted payload fields without derived indexes
- Backward-compatible re-encryption of existing plaintext rows at scale
- KMS provider-specific SDK integration (AWS KMS, GCP CKMS, Azure Key Vault) — the RFC
  describes the envelope model; provider integration is BYOK2 scope

---

## 3. Key Classes

ShadowAI uses several distinct classes of cryptographic key material. BYOK1 concerns
**encryption keys** only. The other classes must remain separate.

| Class | Purpose | Current holder | Rotation | BYOK target |
|-------|---------|----------------|----------|-------------|
| **Integrity keys** | HMAC chain (`AUDIT_CHAIN_SECRET`) — proves row order and non-deletion | Operator env var | W7 ChainSecretKeyring | No |
| **Signing keys** | Ed25519 private key for anchor manifests | Operator env var (signing scheduler only) | W7 SigningKeyring | No |
| **Encryption keys (DEK)** | Payload field encryption (BYOK1 scope) | Not implemented | Envelope re-wrap | Yes — customer root key wraps DEK |
| **Auth/session secrets** | JWT signing, session tokens | Operator env var | Independent | No |
| **Token secrets** | `LEGAL_HOLD_TOKEN_SECRET` (case_ref HMAC) | Operator env var | Independent | No |

**Critical invariant**: integrity keys and encryption keys must remain independent.
Knowledge of the DEK must not imply knowledge of `AUDIT_CHAIN_SECRET`, and vice versa.
A DBA who extracts the DEK from KMS cannot forge chain hashes; a DBA who steals the chain
secret cannot decrypt encrypted payload.

---

## 4. Threat Model

### 4.1 Threat actors

| Actor | Access level | BYOK mitigation goal |
|-------|-------------|----------------------|
| **DBA** | Full DB read/write | Cannot read encrypted payload without KMS access |
| **Compromised app server** | App secrets, DB connection | KMS call still requires customer root key authorization |
| **KMS unavailable** | Availability attack | Reads of encrypted payload fail; WORM verification still works (uses public key only) |
| **Customer revokes key** | DEK unwrap fails | Payload becomes unreadable; audit proof-of-existence (chain, Merkle roots) remains intact |
| **Tenant admin** | Org-scoped data | Can only access their own tenant's DEK; cannot read other tenants' encrypted payload |
| **Global admin** | Cross-tenant read | Cannot decrypt without per-tenant KMS authorization; encrypted payload is opaque |

### 4.2 What BYOK does NOT protect against

- Application-level reads that happen before encryption (audit log creation)
- Compromise of the encryption service that holds unwrapped DEK in memory
- Side-channel attacks through derived indexes / tokenized fields
- Metadata (user_id, org_id, seq_no, timestamps) — these remain unencrypted to support
  chain verification, querying, and index integrity

---

## 5. Field Classification

The following table classifies `audit_logs` fields by encryptability. Similar analysis
applies to `admin_event_logs`, `legal_holds`, and `user_erasure_runs`.

| Field | Current usage | Encrypt? | Search impact | Evidence/WORM impact |
|-------|--------------|----------|---------------|----------------------|
| `id` | PK, FK references | No | Required | In canonical hash (identity) |
| `user_id` | FK, legal hold check, DSAR | Partial (tokenize) | Required for hold/DSAR | In canonical hash |
| `org_id` | Tenant filter, routing | No | Required | In canonical hash (v2) |
| `seq_no` | Chain continuity | No | Required (ordering) | In canonical hash |
| `row_hash` | Chain integrity | No | Required (verification) | IS the integrity artifact |
| `model` | Governance, billing | No | Required | In canonical hash |
| `provider` | Governance, SIEM filter | No | Required | In canonical hash |
| `endpoint` | Routing, governance | No | Required | In canonical hash |
| `status_code` | Policy decision | No | Required | In canonical hash |
| `prompt_tokens`, `completion_tokens` | Budget accounting | No | Required | In canonical hash |
| `cost_usd` | Budget accounting | No | Required | In canonical hash |
| `pii_detected` | DLP flag | No | Required for DLP reporting | In canonical hash |
| `pii_types` | DLP metadata | Partial (enumerated) | Required for DLP | In canonical hash |
| `policy_action` | Security verdict | No | Required | In canonical hash |
| `outcome` | Transport status | No | Required | In canonical hash |
| `created_at` | Ordering, retention | No | Required | In canonical hash |
| `request_body` | LLM prompt payload | **Yes** | Not indexed | NOT in canonical (payload audit only) |
| `response_body` | LLM response payload | **Yes** | Not indexed | NOT in canonical (payload audit only) |
| `canonical_version` | Canonical dispatch | No | Required | In canonical hash |
| `fallback_reason`, `usage_source` | Transport metadata | No | Required | In canonical hash |

**Key finding**: `request_body` and `response_body` are the primary candidates for
field-level encryption. All fields that appear in the WORM canonical hash must remain
plaintext (or have a deterministic plaintext representation) for integrity verification.

---

## 6. Canonical / WORM Interaction

### 6.1 Current canonical model

The WORM canonical (W2, `chain.CanonicalAuditLog*`) is a deterministic string over
normalized field values:

```
v2|user_id|model|provider|endpoint|status_code|...|org_id
```

The HMAC chain: `row_hash = HMAC-SHA256(prev_row_hash || canonical, AUDIT_CHAIN_SECRET)`.

### 6.2 Problem with naive full-row encryption

If `user_id` were encrypted, the canonical would include ciphertext. But ciphertext is
non-deterministic (IV-dependent), so the same logical row would produce a different hash
on every encryption attempt, breaking chain re-verification.

### 6.3 Recommended design: encrypt-after-canonical

**Encryption happens AFTER canonical computation and AFTER chain hash assignment.**

```
INSERT flow:
  1. Compute canonical(row) over plaintext fields
  2. Compute row_hash = HMAC(prev_hash || canonical, chain_secret)
  3. Encrypt encryptable fields (request_body, response_body) with DEK
  4. Store: plaintext chain fields + encrypted payload + row_hash

Verification flow:
  1. Read plaintext fields + row_hash
  2. Recompute canonical(plaintext fields)
  3. Verify HMAC chain — no DEK required
  4. Optionally: unwrap DEK → decrypt payload for audit review
```

This means:
- **Chain integrity can be verified without KMS access** (encrypted payload is not in canonical)
- **Evidence bundles remain verifiable** even after key revocation — verifier only needs the chain fields and public anchor signing key
- **DBA cannot forge chain hashes** even if they extract the DEK

### 6.4 Envelope structure

Each encrypted field uses an envelope:

```json
{
  "v":    1,
  "alg":  "AES-256-GCM",
  "kid":  "tenant:org-uuid:dek-id:2026-Q1",
  "iv":   "base64...",
  "tag":  "base64...",
  "ct":   "base64..."
}
```

The `kid` (key ID) references the KMS-wrapped DEK. The envelope metadata (`kid`, `alg`, `iv`)
is stored alongside ciphertext to enable future key rotation (re-wrap DEK, re-encrypt
`ct` with new DEK, update `kid`).

### 6.5 What the WORM canonical covers

| Data | In canonical | In evidence bundle |
|------|-----------|--------------------|
| Chain fields (user_id, model, provider, ...) | Yes — plaintext | Yes — plaintext |
| request_body / response_body | No | Encrypted envelope (verifiable by existence, not content) |
| Envelope metadata (kid, iv) | No | Yes — for re-decryption |
| row_hash | Not hashed (is the hash) | Yes |
| Anchor Merkle root | Computed over row_hashes | Yes |
| Anchor Ed25519 signature | Signs canonical (manifest) | Yes |

**Consequence**: an auditor can verify chain and anchor integrity without decrypting
payload. They can prove the audit log existed and was not tampered, but cannot read
the LLM conversation content without KMS access. This is the correct separation:
*proof-of-existence / tamper-evidence* does not require *payload disclosure*.

---

## 7. Key Hierarchy

### 7.1 Structure

```
Customer Root Key (CRK)
└── Tenant Key Encryption Key (KEK)  [per org_id, wrapped by CRK in KMS]
    └── Data Encryption Key (DEK)     [per-rotation epoch, wrapped by KEK]
        └── Field ciphertext          [AES-256-GCM per field, keyed by DEK]
```

### 7.2 Key lifecycle

- **CRK**: Customer-managed, stored in customer's KMS. ShadowAI never sees it.
- **KEK**: Derived per tenant, wrapped (encrypted) by CRK. ShadowAI stores the wrapped form.
- **DEK**: Generated per epoch (e.g., quarterly rotation). ShadowAI holds the wrapped DEK;
  unwrap requires KMS call. DEK is cached in memory for the encryption service lifetime;
  never written to DB in plaintext.
- **IV/nonce**: Generated per field per row. Stored in envelope.

### 7.3 Key ID format

```
tenant:<org_id>:dek:<YYYY-QN>
```

Example: `tenant:aaaaaaaa-0000-4000-8000-000000000001:dek:2026-Q1`

This format supports the W7 keyring model: the verifier loads the epoch → DEK mapping
from a keyring file for bulk re-encryption or verification tasks.

---

## 8. Tenant Isolation and BYOK

### 8.1 Per-tenant key material

Each tenant (`org_id`) has its own KEK/DEK chain. Cross-tenant data is protected because:
- Tenant A's DEK cannot decrypt Tenant B's ciphertext (different `kid`, different KEK)
- Global admin reads `ct` but gets an opaque blob without access to the tenant's CRK

### 8.2 Global admin limitations

With BYOK enabled, `global_admin` operations on audit payload fields are limited:
- Chain fields (user_id, org_id, model, etc.): readable by global_admin (not encrypted)
- request_body / response_body: **opaque** — requires tenant-specific KMS authorization
- This is the intended design: global_admin can perform operational tasks (chain verify,
  anchor management, purge coordination) without reading tenant conversation content

### 8.3 Tenant bundle implications

Evidence bundle export (`audit-export-evidence --org-id <uuid>`):
- Chain fields, row_hashes, anchor manifests: exported as-is (plaintext)
- Encrypted payload fields: exported as envelopes (ciphertext + kid + iv)
- `bundle_manifest.json` notes encryption presence (`encrypted_fields: ["request_body", "response_body"]`)
- Offline verification: **still works** — verifier uses chain fields + Merkle proofs
- Payload decryption for auditor: requires KMS access with appropriate tenant authorization;
  out-of-scope for BYOK1 tooling (future CLI `audit-decrypt-bundle --kms-endpoint ...`)

---

## 9. Operational Flows

### 9.1 Key rotation (DEK rotation)

```
1. Generate new DEK epoch (dek:2026-Q2)
2. Wrap new DEK with tenant KEK via KMS → store wrapped DEK
3. Re-encrypt old rows: for each row with kid=2026-Q1:
   a. Unwrap old DEK via KMS
   b. Decrypt field with old DEK
   c. Encrypt field with new DEK
   d. Update envelope: new ct, new iv, new kid (=2026-Q2)
   e. row_hash unchanged (plaintext fields unchanged)
4. Old wrapped DEK archived (for backward-compatible verification of old envelopes
   until re-encryption is complete)
```

**Duration**: Re-encryption is a background migration. During migration, rows may have
mixed `kid` values. The keyring model (W7) already supports this pattern.

### 9.2 Key disable / revoke

When the customer revokes CRK access in their KMS:

- **Immediate effect**: new DEK unwrap calls fail → new writes fail if DEK not cached
- **Reads**: encrypted payload fields become unreadable (DEK unwrap fails)
- **WORM verification**: **unaffected** — chain fields and row_hashes remain accessible;
  Merkle anchor verification does not require DEK
- **Legal hold**: continues to block DSAR — hold status is in unencrypted `status` field
- **Audit proof**: chain + anchor proofs remain valid; "the data existed" can still be proven
- **Impact**: customer accepts that payload is inaccessible; they retain proof-of-existence

**Operator response**: document in incident log. Do not attempt to re-derive key.
The chain proof that the encrypted row existed is itself a compliance artifact.

### 9.3 Restore from backup

DB restore into a new environment:
1. Restore DB — rows contain: plaintext chain fields + encrypted envelopes + row_hashes
2. WORM chain verification: runs normally (no KMS required)
3. Anchor verification: runs normally (no KMS required, uses public anchor signing key)
4. Evidence bundle verify: runs normally (bundle_verify only needs chain fields)
5. Payload access: requires KMS access with tenant KEK → if customer KMS is available,
   envelopes can be re-decrypted; otherwise payload is inaccessible

### 9.4 Evidence verification without decryption

`audit-verify --bundle <dir>` continues to work without KMS because:
- `bundle file_integrity` check: SHA256 of files (not payload content)
- `bundle sigs` check: Ed25519 over anchor manifest canonical (covers chain fields, not payload)
- `bundle anchor_range audit_logs` check: Merkle over row_hashes (derived from chain fields)
- `bundle inventory audit_logs` check: chain continuity (seq_no, row_hash linkage)

None of these verification steps require decrypting payload. An auditor can receive
an evidence bundle and verify its integrity without the customer's KMS credentials.

### 9.5 SIEM mirror with BYOK

Two options for SIEM delivery:
1. **Minimized metadata only**: SIEM receives chain fields (user_id, model, provider, status,
   policy_action, timestamps) + encrypted envelope metadata (kid, row existence). Payload
   not mirrored.
2. **Selective decryption gateway**: A separate service unwraps DEK and decrypts before
   SIEM delivery. This service has its own authorization boundary and key usage audit trail.

Option 1 is the safer default for BYOK deployments. SIEM should never receive plaintext
payload "for free" just because encryption is in use at the DB layer.

---

## 10. Migration Path

### 10.1 New deployments (greenfield)

1. Enable BYOK at provisioning: configure KMS endpoint, provision tenant KEK
2. All writes encrypted from day zero
3. No plaintext rows in DB
4. DEK rotation scheduled (quarterly default)

### 10.2 Existing plaintext deployments

Migration from plaintext to encrypted has two phases:

**Phase 1 — Dual-write (shadow)**:
- New rows written with encryption
- Old rows remain plaintext
- Reads: check `kid` field; if empty → plaintext read; if present → decrypt
- Evidence bundle: `encrypted_fields` partially populated

**Phase 2 — Background encryption sweep**:
- Iterate old rows with missing `kid`
- Encrypt payload fields, set envelope, set `kid`
- row_hash **unchanged** (chain fields unchanged)
- This is a long-running background job; no downtime required

**Phase 3 — Enforce**:
- Application rejects plaintext reads (no `kid` → error)
- All rows encrypted
- Evidence bundle: `encrypted_fields` fully populated

### 10.3 Mixed encrypted/plaintext period

During Phase 1/2, both paths must work:
- `kid` present → decrypt via KMS → return plaintext to application
- `kid` absent → return field as-is (plaintext)
- WORM verification: **unaffected** — chain hash covers same plaintext chain fields in both cases

The `kid` field itself must be indexed for efficient sweep queries.

---

## 11. Risks and Residual Gaps

| Risk | Severity | Mitigation in this design | Residual |
|------|----------|--------------------------|----------|
| KMS unavailable → write failures | High | DEK caching in memory (bounded TTL) | Outage during cache miss; KMS availability becomes critical path |
| KMS unavailable → read failures for encrypted payload | High | Chain/anchor verification unaffected; payload reads fail gracefully | Customer must operate KMS with SLA matching their compliance requirements |
| Re-encryption sweep incomplete → mixed state | Medium | `kid` field distinguishes rows; dual-read path | Long-lived partial migration state increases operational complexity |
| Side-channel from derived indexes | Medium | Keep indexed fields (user_id, org_id, model) plaintext or tokenized | Tokenized user_id is still fingerprintable if dictionary is small |
| DEK in memory → compromise during app server attack | High | DEK cached for bounded TTL; KMS call per epoch boundary | In-memory DEK exposure window; HSM would close this gap (BYOK2 scope) |
| Evidence bundle payload unreadable after key revocation | Medium | Proof-of-existence via chain + anchors remains intact | Auditor cannot read conversation content; by design for revoked keys |
| Legal hold interacting with encrypted payload | Medium | Hold status in unencrypted `status` field; hold blocks DSAR independent of KMS | If hold reason / notes were encrypted, legal team loses access after revocation |
| SIEM receiving ciphertext only | Low | Option 1 (minimized metadata) defined explicitly | SIEM use-cases requiring payload content need Option 2 (decrypt gateway) |
| Tenant isolation failure via global admin | Low | Global admin cannot decrypt without tenant CRK authorization | Insider threat with both global_admin DB access and CRK access is not mitigated |

---

## 12. Open Questions

BYOK2 v1 resolution:

- First backend: HashiCorp Vault Transit.
- First fields: `audit_logs.request_body` and `audit_logs.response_body`.
- Rollout: new-writes-only + dual-read legacy plaintext/envelope.
- Deferred: per-tenant DEK epoch storage, background re-encryption sweep, searchable encryption, legal-hold selector encryption.

Remaining questions for BYOK v2+:

1. **DEK caching TTL**: What is the acceptable window for in-memory DEK exposure?
   Shorter TTL → more KMS calls; longer TTL → larger breach window.

2. **Payload audit depth**: Should `request_body` / `response_body` be included in
   Merkle-hashed row inventory (using ciphertext as the leaf), or remain outside the
   chain entirely? Including ciphertext in Merkle provides stronger proof-of-content-existence.

3. **Legal hold notes**: Are `holds.reason` and `holds.case_ref` considered payload
   (encrypt) or metadata (keep plaintext)? The design here assumes metadata; if they are
   payload, legal hold events need separate treatment.

4. **DSAR compliance with encrypted payload**: If a user's request_body is encrypted with
   a key the user cannot directly obtain, does erasure need to include key deletion
   ("cryptographic erasure") in addition to data deletion?

5. **Searchable encryption**: Some regulated use cases require query on encrypted fields
   (e.g., "all requests from user X" on an encrypted user_id). Is tokenization
   (HMAC-truncated `user_id` → `user_id_token` stored plaintext) acceptable as a substitute?

---

## 13. Relationship to Existing Features

| Feature | BYOK interaction |
|---------|-----------------|
| W2 HMAC chain | Canonical over plaintext chain fields; encryption does not affect chain |
| W3/W4 Merkle anchors + Ed25519 | Anchors cover row_hashes derived from plaintext; unaffected |
| W5/W6 evidence bundles | Export chain fields + envelopes; verify without KMS |
| W7 key epochs | DEK rotation reuses W7 keyring model (`kid` maps to ChainEpoch-equivalent) |
| T2 tenant isolation | Per-tenant DEK; global_admin cannot decrypt cross-tenant |
| L5 legal hold | Hold status unencrypted; hold blocks DSAR independent of KMS availability |
| DSAR/erasure | Erasure + cryptographic erasure (DEK deletion) provides double-guarantee |
| G1-G4 governance | Governance decisions logged in chain fields; request/response payload encrypted |
| SIEM S1.1 | Mirror minimized metadata by default; decrypt-gateway for full payload |

---

## 14. Recommended Next Steps (BYOK2 scope)

When implementation begins:

1. Implement per-tenant DEK epoch metadata (`kid` → tenant/key epoch) on top of the BYOK2 envelope.
2. Implement background re-encryption sweep job for legacy plaintext rows.
3. Add `encrypted_fields` to bundle manifest format.
4. Extend operator tooling with decrypt-on-demand flow for authorized tenant auditors.
5. Add additional customer KMS backends after provider-specific requirements are known.

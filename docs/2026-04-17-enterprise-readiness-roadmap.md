# ShadowAI Enterprise Readiness Roadmap

Дата: 2026-04-26
Статус: актуализировано после E1/E2/E3, T2/T3, G4, W5.2/W6, O4.4 и SIEM v1.1.

## Цель

Документ фиксирует фактический enterprise-readiness status ShadowAI и текущий порядок следующих работ:

1. **enterprise pilot ready** — self-hosted или dedicated-tenant deployment с защищаемым identity, governance и compliance story.
2. **signed production ready** — production deploy с operational runbooks, audit evidence, alerting и восстановимой chain-of-custody.
3. **broader GA / hardened default** — high-traffic, multi-tenant/SaaS posture, performance/caching, key rotation и formal compliance mapping.

---

## Текущее состояние

### Закрыто

| Трек | Статус | Что теперь есть |
|------|--------|-----------------|
| Admin audit / user-admin trail | ✅ | admin events, org/source/target org context, SIEM-visible forensic trail |
| DSAR / erasure | ✅ | user erasure/anonymization flow, idempotent path, audit trail |
| Legal hold L1-L4 | ✅ | 4-eyes apply workflow, active hold blocks DSAR, retention-aware purge, advisory-lock coordination, live PG tests |
| SIEM S1/S1.1 | ✅ | HTTP mirror, prod guards, async queue, batching, retry, backpressure, graceful drain |
| Governance G1-G4 | ✅ | provider/model allowlist, role-based rules, department/sensitivity routing, org-level aggregate budget caps |
| Streaming firewall F7 | ✅ | provider adapters, incremental inspection, structured audit outcomes, shadow compare, partial usage semantics |
| Firewall hardening F8 | ✅ | semantic_v2 shadow_only rollout, would_block metric, prod fail-fast, accurate streaming prod gate wording |
| Identity E1/E3 | ✅ | OIDC login, group/role mapping, IdP MFA claim enforcement, local MFA, break-glass, admin MFA policy |
| SCIM E2 | ✅ | SCIM 2.0 lifecycle, per-org bearer tokens, role/department sync, deprovision token invalidation |
| Tenant isolation T1/T2 | ✅ | org schema, org-scoped repositories/APIs, global_admin org control plane, tenant purge/export boundaries |
| Tenant evidence T3/W6 | ✅ | tenant Merkle subset proofs; tenant bundles do not expose cross-tenant row hashes |
| WORM / evidence W1-W5.2 | ✅ | HMAC chain, Merkle anchors, Ed25519 manifests, file/immudb sinks, live immudb v2 integration, portable offline bundle |
| Evidence ops O4.1-O4.4.1 | ✅ | scheduled export, S3 backend, Object Lock, retention audit report; EvidenceAuditReportJobFailed/Missing alerts; all violation codes documented |
| Production ops O1/O3 | ✅ | Docker/Helm, migrations init, health/readiness, Prometheus alerts, smoke harness, deploy runbooks |
| CI / release gates | ✅ | core/enterprise/integration/smoke tests, Docker build, Helm validate, migration smoke, security jobs |
| Prod config hardening | ✅ | startup fail-fast for unsafe production config across auth/SIEM/legalhold/WORM/SA_v2/OIDC/SCIM |
| LLM security validation SEC1 | ✅ | external assessor package: scope, rules of engagement, attack matrix, safe test corpus, evidence workflow and remediation template |

### Что это означает

- **Enterprise pilot ready:** да, для controlled self-hosted или dedicated-tenant deployment, если operator выполняет production checklist и secrets/bootstrap корректны.
- **Signed production ready:** близко к да. Остались в основном documentation/control-mapping и performance hardening, а не фундаментальные security gaps.
- **Compliance evidence story:** сильная. Есть tamper-evident DB chain, external anchors, signed manifests, S3 Object Lock и portable auditor bundles.
- **Multi-tenant posture:** базовый product-complete. Есть org boundary в runtime, SCIM, audit, governance, purge/export и tenant proofs.
- **LLM firewall runtime:** защищаемый. Остаётся Stage 2 sanitize/promotion work, но streaming больше не является blocker для enterprise pilot.

---

## Требует доработки

### ~~Immediate Cleanup~~ (закрыто)

~~1. **O4.4.1 docs cleanup** — закрыто в сессии 2026-04-26:~~
- ~~`EvidenceExportJobFailed` → `EvidenceAuditReportJobFailed` в CronJob template и runbook.~~
- ~~`missing_retention`, `manifest_read_error` добавлены в violation table runbook.~~

~~2. **Roadmap sync** — этот документ.~~

### Production Hardening

3. **G2.2: governance policy cache**
   - Сейчас policy evaluation корректна, но high-traffic proxy не должен зависеть от DB read на hot path.
   - Нужен immutable in-memory snapshot, refresh на policy update, TTL fallback, cache-staleness metrics, fail-closed on corrupt policy.

4. **F7.5: streaming Stage 2**
   - Incremental sanitize semantics.
   - Promotion criteria для снятия prod opt-in gate: fallback/error budget, shadow mismatch rate, provider-specific confidence.
   - Решение по legacy buffered path только после production proof window.

5. **Legal hold v3**
   - Hold scope шире whole-user: date-range / query-scope holds.
   - Release 4-eyes.
   - SLA escalation, bulk approvals, pending queue operations.

6. **W7: evidence operations hardening**
   - Key rotation для `AUDIT_CHAIN_SECRET` и Ed25519 anchor signing.
   - Automated restore verification drill.
   - Optional second independent anchor sink.
   - Evidence audit reports as archived artifacts, если аудиторам нужен scheduled report bundle, а не только Job logs/manual output.

### Compliance / Enterprise Review

7. **SOC 2 / ISO readiness mapping**
   - Controls inventory.
   - Control owner, evidence artifact, cadence, retention, alert.
   - Mapping реализованных technical controls к SOC 2 / ISO 27001 evidence.

8. **BYOK / KMS / encryption controls**
   - Customer-managed key story.
   - KMS integration points.
   - Field-level encryption hooks for audit-sensitive fields.

9. **Alert coverage refinement**
   - Legal hold pending/SLA alerts.
   - SIEM queue/drop/retry dashboards.
   - semantic_v2 `fail_open` / `would_block` promotion dashboards. **[implemented: F8.1]**
   - Evidence audit report alerts are implemented, but operator docs still need final cleanup.

---

## Next 0-30 Days

### ~~PR-G2.2: Governance Policy Cache~~ ✅

Закрыто 2026-04-26: `CachingRepository` с per-org in-process snapshot,
write-through Upsert, TTL fallback (60s), fail-closed на reload error,
Prometheus metrics `shadowai_governance_cache_*`, go test -race зелёный.

### PR-SOC1: Controls Mapping v1 ← **current**

**Цель:** превратить технический readiness в audit-ready material для sales/security review.

**Документ:** [`docs/compliance/soc2-iso-control-mapping.md`](compliance/soc2-iso-control-mapping.md)

Закрыто 2026-04-26. Содержит:
- Mapping на SOC 2 TSC и ISO 27001:2022 по 10 категориям controls.
- Для каждого control: objective, implementation, evidence artifact, owner, cadence, residual gap.
- Раздел «Current Gaps / Not Covered» с явными честными gaps.
- Раздел «How to Use in Security Questionnaire».
- Evidence Artifact Quick Reference.
- Disclaimer: not a certification / not legal attestation.

---

## Next 30-60 Days

### PR-F7.5: Streaming Stage 2

Scope:

- Incremental sanitize для response streaming.
- Provider-specific promotion criteria.
- Shadow mismatch budget и fallback budget.
- Decision по `STREAMING_ALLOW_INCREMENTAL_IN_PROD` после proof window.

Acceptance criteria:

- Streaming sanitize не требует full-buffer fallback для базовых text deltas.
- Operators видят rollout safety через metrics/audit outcomes.

### PR-W7: Key Rotation and Restore Automation

Scope:

- Chain/signing key rotation policy.
- Verifier support for key epochs.
- Scheduled restore verification job or documented automation.
- Optional second sink support if required by target customers.

Acceptance criteria:

- Rotation не ломает старую evidence verification.
- Restore drill можно запускать воспроизводимо без ручного runbook-heavy процесса.

### PR-L5: Legal Hold Advanced Workflow

Scope:

- Release 4-eyes.
- SLA escalation.
- Bulk approve/reject.
- Scope beyond whole-user.

Acceptance criteria:

- Legal team может управлять большим backlog holds без ручных SQL/scripts.
- Release path имеет тот же control strength, что apply path.

---

## Next 60-90 Days

### PR-BYOK1: KMS / BYOK Design

Scope:

- RFC: key ownership, envelope encryption, rotation, audit fields.
- Decide managed KMS vs customer-provided keys vs self-hosted Vault.
- Define fields eligible for encryption without breaking search/audit.

Acceptance criteria:

- Есть defendable answer на вопрос "как клиент контролирует ключи".
- Implementation path не ломает WORM canonical/hash chain assumptions.

### PR-GA1: Hardened Default / Scale Pass

Scope:

- Load profile for proxy hot path after governance cache.
- Streaming latency/memory budget validation.
- SIEM queue sizing recommendations.
- Helm production defaults review.

Acceptance criteria:

- Документированный supported throughput profile.
- Defaults безопасны для medium enterprise install.

---

## Deferred / Explicitly Not Now

- Удаление buffered streaming path до production proof window.
- Большой analytics UI до завершения SOC/control mapping.
- Full BYOK implementation — RFC завершён (BYOK1), реализация в BYOK2 после customer requirement и KMS provider decision.
- Multi-region active-active до key rotation / evidence restore automation.
- Поддержка SAML, если OIDC покрывает целевые IdP.

---

## Current Priority Order

1. ~~**O4.4.1 — Evidence audit report docs cleanup**~~ ✅
2. ~~**G2.2 — Governance policy cache**~~ ✅
3. ~~**SOC1 — SOC 2 / ISO control mapping**~~ ✅ → `docs/compliance/soc2-iso-control-mapping.md`
4. ~~**F7.5 — Streaming Stage 2**~~ ✅
5. ~~**W7 — Key rotation + restore automation**~~ ✅
6. ~~**L5 — Legal hold advanced workflow**~~ ✅
7. ~~**BYOK1 — KMS / BYOK design**~~ ✅ → `docs/rfcs/2026-04-pr-byok1-kms-byok-design.md`
8. ~~**GA1 — Hardened default / scale pass**~~ ✅ → `docs/production-hardening.md`
9. ~~**F7.6 — Streaming production proof window**~~ ✅ → `docs/runbooks/streaming-production-proof.md`
10. **SOC2.1 — Evidence collection automation** ← current → `docs/runbooks/evidence-collection.md`

---

## Decision Point

Главный принцип теперь:

- **До enterprise pilot:** фундаментальные blockers закрыты; нужен только deployment-specific checklist и clean docs.
- **До signed production:** ✅ все закрыты.
- **До broader GA:** ✅ GA1 (hardened defaults/scale pass) закрыт; остаются BYOK2 (после customer demand) и L6 (scoped holds).

Следующий recommended work item: **F7.6 streaming proof window** (оперативная задача: запустить и пройти 30-day process), затем **BYOK2** или **L6**.

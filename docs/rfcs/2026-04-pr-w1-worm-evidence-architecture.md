# RFC: PR-W1 — WORM / Tamper-Evident Evidence Architecture

| Field   | Value                                                                                     |
|---------|-------------------------------------------------------------------------------------------|
| Status  | Draft                                                                                     |
| Date    | 2026-04-23                                                                                |
| Owners  | ShadowAI maintainers                                                                      |
| Scope   | `audit_logs`, `admin_event_logs`, SIEM mirror, backup/restore, legal hold interaction     |
| Related | PR-S1 (SIEM mirror), PR-D (admin audit), PR-L2.3 (legal hold), PR-F7.3 (streaming audit) |

---

## 1. Summary

Этот RFC описывает архитектуру tamper-evident / tamper-resistant evidence для
ShadowAI: как обеспечить, что `audit_logs` и `admin_event_logs` не могут быть
тихо модифицированы, удалены или переупорядочены без обнаруживаемого следа,
при этом сохраняя self-hosted deploy pragmatism, core/enterprise split и
legibility для compliance auditor'ов.

Цель: после W1 RFC можно открывать W2 (minimal chain + verifier) без
повторной архитектурной дискуссии.

---

## 2. Problem Statement

### 2.1 Текущее состояние

`audit_logs` (core migration 002/009):
- Хранятся в PostgreSQL. Admin с прямым DB-доступом может `UPDATE`, `DELETE`,
  `ALTER TABLE` без application-level следа.
- Retention purge (`cmd/audit-purge`, scheduler) делает легальное soft-delete —
  отличить законный purge от злонамеренного удаления на уровне таблицы
  невозможно после факта.
- Restore-from-backup может тихо переписать историю (backup был сделан до
  инцидента).

`admin_event_logs` (enterprise migration 010):
- Аналогичная проблема: `actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL`
  означает, что удаление пользователя обнуляет actor на всех его event'ах.
- Нет hash chain, нет sequence integrity.

SIEM mirror (PR-S1):
- Fail-open HTTP push. SIEM получает копию, но:
  - Outage SIEM = loss of secondary copy without notification.
  - Sequence gaps — нет explicit counter per-row, gap невозможно отличить
    от "normal" purge.
  - SIEM — secondary consumer, не source of truth. Нет cross-reference
    mechanism, позволяющего доказать, что основная БД и SIEM зеркало согласованы.

### 2.2 Gap в одном предложении

Текущая архитектура обеспечивает **availability и queryability** audit trail,
но не обеспечивает **integrity detectability** при compromised DBA или
compromised infrastructure.

### 2.3 Что считается Evidence

В контексте ShadowAI evidence — это запись, которую **регулятор, юрист или
forensic analyst** может использовать для ответа на вопросы:

- Кто и когда делал конкретный запрос к LLM?
- Было ли data erased? Когда? Кем?
- Применялся ли legal hold? Был ли он approved и кем?
- Не было ли записи retroactively изменены или удалены?

Evidence trail должна быть:
- **Authentic** — запись пришла именно от ShadowAI, в то время, которое указано.
- **Integral** — запись не была изменена после creation.
- **Complete** — пропуски в последовательности обнаруживаемы.
- **Non-repudiable** — creator'у сложно отрицать создание записи.

---

## 3. Threat Model

### 3.1 Attacker models (в порядке убывания вероятности для enterprise self-hosted)

**T1 — Malicious DBA with direct DB access** (наиболее критичный для
enterprise deploy)

- Вектор: `psql` / DB management tool, прямой INSERT/UPDATE/DELETE на
  `audit_logs`/`admin_event_logs`.
- Цель: скрыть evidence о собственных действиях (erase без approval,
  governance bypass, data exfil) или подделать чужие.
- Детектируемость сейчас: НУЛЕВАЯ если SIEM не писал event до удаления,
  или если attacker также имеет доступ к SIEM.

**T2 — Compromised application host**

- Вектор: компрометация приложения или reverse proxy, дающая доступ к
  DB connection string. Attacker может инъецировать или модифицировать
  audit entries через app layer.
- Детектируемость сейчас: НУЛЕВАЯ — application пишет напрямую в БД
  без signing.

**T3 — Delayed SIEM outage / dropped mirror**

- Вектор: сеть недоступна, SIEM перегружен, SIEM webhook вернул 5xx.
  PR-S1 fail-open → events потеряны в secondary copy без alert'а.
- Детектируемость сейчас: ОГРАНИЧЕННАЯ — `shadowai_siem_drop_total`
  метрика отслеживает drops, но нет per-row sequence для reconciliation.

**T4 — Insider retroactively deleting rows**

- Вектор: admin запускает несанкционированный retention purge или
  прямой DELETE вне scheduler workflow.
- Детектируемость сейчас: нет последовательного chain — gap не
  обнаруживается по таблице.

**T5 — Restore-from-backup rewriting history**

- Вектор: backup сделан до инцидента. Restore тихо откатывает все
  записи до snapshot'а. Новые записи после restore создаются, как будто
  rollback не был.
- Детектируемость сейчас: НУЛЕВАЯ — нет external anchor для сравнения.

### 3.2 Non-threats (out of scope для W1)

- Аппаратный compromised hardware / side-channel attacks.
- Quantum-resistant cryptography (Ed25519 достаточен для 10+ лет).
- Multi-tenant isolation (отдельный трек).
- Attacker с полным filesystem access к PG data directory — это
  threat, требующий WORM primary store (W3).

---

## 4. Hard Invariants

Следующие свойства должны выполняться после W3 (полная реализация),
и частично — уже после W2:

1. **Integrity-detectable**: модификация любой audit row должна привести
   к detectable cryptographic mismatch без необходимости сравнивать
   с external source.
2. **Gap-detectable**: удаление или пропуск любой audit row должен
   обнаруживаться offline verifier'ом без доступа к основной БД.
3. **No silent rewrite**: restore-from-backup не может тихо убрать записи,
   существовавшие в момент последнего external anchor.
4. **Queryable local trail**: существующий API для `audit_logs` и
   `admin_event_logs` продолжает работать без деградации.
5. **Self-hosted practical**: реализация не требует vendor-specific cloud
   (S3, CloudTrail, Blockchain) в базовой конфигурации. Все компоненты
   должны быть deployable on-premises.
6. **Core/enterprise split**: chain и WORM sink — enterprise feature.
   Core build работает без chain (отсутствие chain = reduced guarantee,
   явно документируется).
7. **Legal hold integration**: row под active legal hold не должна
   быть purge'абельна ни через scheduler, ни через manual DELETE.
   Chain должна включать legal hold state как проверяемый факт.

---

## 5. Current Architecture Surface

### 5.1 Evidence tables (today)

```
audit_logs               — core (002/009). ~high volume. retention purge.
admin_event_logs         — enterprise (010). low volume. static retention.
user_erasure_runs        — enterprise (009). DSAR tombstone.
audit_purge_runs         — core (008). purge metadata.
legal_holds              — enterprise (013/015). hold state machine.
```

### 5.2 SIEM mirror (today)

```
adminaudit.FanOutRecorder → HTTP POST (fail-open) → external SIEM
```

Покрывает: `admin_event_logs` только. `audit_logs` в SIEM не идут
(volume слишком высокий для неструктурированного HTTP push по умолчанию).

### 5.3 What exists vs. what is needed

| Property              | audit_logs (today) | admin_event_logs (today) | Required   |
|-----------------------|--------------------|--------------------------|------------|
| Row-level signing     | No                 | No                       | W2         |
| Hash chain            | No                 | No                       | W2         |
| Sequence counter      | No                 | No                       | W2         |
| External anchor       | No                 | SIEM (weak)              | W3         |
| Verifier tool         | No                 | No                       | W2/W3      |
| Gap detection         | No                 | No                       | W2         |
| Backup restore guard  | No                 | No                       | W3         |

---

## 6. Alternatives Considered

### A. Append-only PostgreSQL triggers only

**Mechanics**: trigger на UPDATE/DELETE → физически запрещает. PG role
separation (app user = INSERT-only).

**Pros**:
- Zero new infrastructure.
- Queryability preserved.
- Cheap operationally.

**Cons**:
- DBA с `SUPERUSER` может DROP TRIGGER, ALTER TABLE, затем делать что
  угодно — и восстановить триггер.
- Нет cryptographic integrity — attacker с `SUPERUSER` переписывает
  данные, включая `created_at`, незаметно.
- Backup restore обходит все триггеры.

**Verdict**: ❌ Недостаточно для T1/T5. Полезно как layer of defence,
но не как primary evidence mechanism.

---

### B. Row-level HMAC in PostgreSQL (no external component)

**Mechanics**: при INSERT каждая row получает HMAC(prev_row_hash || row_data,
secret). Verifier проверяет chain offline. Secret хранится в HSM или
env var.

**Pros**:
- Self-contained: нет внешних сервисов.
- Chain-level integrity — gap и reorder detectable.
- Reasonable implementation cost.

**Cons**:
- Secret должен быть недоступен DBA. Если секрет compromised → attacker
  может сгенерировать валидные re-hashed rows.
- HMAC не является non-repudiable — любой с секретом может подписывать.
- Backup restore неотличим по chain если backup взят после re-signing.
- Нет external witness — chain самосогласована, но внешний audit'ор
  не может верифицировать без доступа к секрету или БД.

**Verdict**: ✅ Хорошо для W2 (detect gap/modification если secret
secure), ❌ недостаточно само по себе для T1 если DBA имеет доступ
к secret'у. Используем как primary local mechanism, с external anchor
как witness (W3).

---

### C. Periodic anchored hash chain (Merkle root → external anchor)

**Mechanics**: каждые T секунд вычисляется Merkle root всех новых
rows за период. Root публикуется в external immutable location
(append-only file, SIEM, S3 bucket, public timestamp service).

**Pros**:
- Proof-by-exclusion: auditor может verifyовать что конкретная row
  была в системе в момент anchor'а.
- External anchor независим от компрометации primary DB.
- Computationally cheap — batch операция, не per-row overhead.
- Non-interactive: root можно сохранить в любом immutable format'е.

**Cons**:
- Между anchor'ами — window of vulnerability. За период T rows
  могут быть добавлены и удалены без следа в chain (если anchor
  не было).
- Requires external immutable store — выбор которого влияет на
  self-hosted practicality.

**Verdict**: ✅ Правильный второй layer поверх B. Anchor'ование дополняет
local chain external witness'ом. Anchor interval = key design parameter.

---

### D. External WORM primary store (replacing PG as evidence store)

**Mechanics**: audit rows пишутся сначала в WORM backend
(S3 Object Lock, Azure Immutable Blob, WORM-capable Cassandra
tier, etc.), PostgreSQL остаётся только query-efficient cache.

**Pros**:
- Strongest guarantee: row в WORM backend физически не удаляема
  в compliance retention period.
- T5 (backup restore) не угрожает WORM backend.

**Cons**:
- Vendor-specific cloud: S3 Object Lock привязывает к AWS.
- Self-hosted complexity резко возрастает — нет готового
  self-hosted WORM за разумную цену.
- Dual-write latency — приложение должно ждать WORM write
  на hot path; fail semantics сложны.
- Core/enterprise split ломается для всех deploy'ев.

**Verdict**: ❌ Out of scope для W1/W2. Возможен как W3+ option для
cloud/SaaS deploy'ев. Не делаем обязательным.

---

### E. SIEM as primary immutable store

**Mechanics**: trust SIEM (Splunk, Elastic, etc.) как immutable copy.
PG остаётся secondary/query-only.

**Pros**:
- Operator уже часто имеет enterprise SIEM.
- SIEM vendor обычно имеет WORM tier.

**Cons**:
- Fail-open mirror (PR-S1) имеет gaps — SIEM не всегда complete.
- SIEM покрывает только `admin_event_logs`, не `audit_logs`.
- Reverse dependency: корректность PG-записи зависит от
  внешнего сервиса, который мы не контролируем.
- Self-hosted deploy без SIEM теряет весь evidence story.
- Sequence ordering в SIEM не гарантирован.

**Verdict**: ❌ Как primary — слишком слабо. Как secondary consumer
(anchor point) — valid дополнение в W3.

---

### F. Dual-write local DB + immutable ledger

**Mechanics**: каждая audit write делает два синхронных write'а:
PG (queryable) + append-only ledger (tamper-evident). Ledger может
быть WORM file, external DB с append-only role, или специализированный
ledger (immudb, QLDB).

**Pros**:
- PG queryability preserved.
- Ledger integrity independent of PG.
- Self-hostable варианты существуют (immudb — открытый, self-hosted).

**Cons**:
- Two-phase write complexity — что делать если одна БД success,
  вторая fail?
- Latency на critical path audit writes.
- Ledger выбор влияет на vendor dependency.

**Verdict**: ✅ Правильный long-term direction (W3+). Ledger choice
= key open question. immudb как open-source self-hosted candidate
хорошо выравнивается с our constraints.

---

## 7. Recommended Architecture

### 7.1 Overview

Трёхслойный подход, введённый поэтапно:

```
Layer 1 (W2): Local hash chain in PG
  ├── audit_evidence_chain column (per-row HMAC of prev_hash + row_data)
  ├── sequence_number per table (monotonic, gap-detectable)
  └── verifier CLI: verify chain continuity offline

Layer 2 (W3): Periodic Merkle anchor
  ├── every T minutes: compute Merkle root of new rows
  ├── anchor published to external immutable location
  │   (configurable: append-only local file | SIEM | S3 | immudb)
  └── verifier CLI: verify anchor inclusion for specific rows

Layer 3 (W3+): WORM ledger (optional, cloud/enterprise tier)
  ├── dual-write to append-only ledger (immudb self-hosted or cloud WORM)
  └── full offline verifiability without access to primary DB
```

### 7.2 Layer 1: Local hash chain (W2 scope)

Каждая evidence row при INSERT получает:

- `seq_no BIGINT NOT NULL` — monotonic per-table counter.
  Gap в sequence → detection signal.
- `row_hash BYTEA NOT NULL` — HMAC-SHA256(prev_row_hash || canonical(row_data), chain_secret).
  `prev_row_hash` для первой row = known initializer.
- Chain secret (`AUDIT_CHAIN_SECRET`) — env var, 32+ chars,
  never in DB. Аналогично `LEGAL_HOLD_TOKEN_SECRET`.

**Canonical row data** — детерминированная сериализация значимых полей
(исключаем `created_at` timezone normalization edge cases, берём
UTC epoch). Spec фиксируется в implementation PR (W2).

**Verifier CLI** (`cmd/audit-verify`):
```
audit-verify --table audit_logs --from 2026-01-01 --to 2026-04-23
```
- Проверяет chain continuity (prev_hash matches).
- Проверяет seq_no gaps.
- Reports: OK / CHAIN_BREAK(seq_no=X) / GAP(seq_no=X→Y) /
  ANCHOR_MISMATCH(epoch=T).

**Chain write atomicity (design decision, review fix):**

`prev_row_hash` = hash от предыдущей row в цепочке. Если два concurrent
INSERT'а оба читают "current chain tip" до того, как один из них
commit'ится — оба подпишутся под одним и тем же prev_hash, создав
branch-конфликт. `seq_no` из PG SEQUENCE решает ordering, но НЕ решает
атомарность чтения tip + hash + insert.

**Решение**: `pg_advisory_xact_lock(chain_namespace, table_id)` перед
каждым chain INSERT — та же техника, которую PR-L3 использует для
`pg_advisory_xact_lock(4201, 1)` при apply_hold ↔ purge координации.
Lock держится в рамках транзакции; all chain writes для одной таблицы
сериализуются. Lock released on commit/rollback.

```sql
-- W2 chain write pseudo-code (одна транзакция):
SELECT pg_advisory_xact_lock($chain_ns, $table_id);
SELECT row_hash AS prev_hash FROM <table>
    WHERE seq_no = (SELECT max(seq_no) FROM <table>)
    FOR UPDATE;  -- дополнительный row-lock на tip
INSERT INTO <table> (..., seq_no, row_hash)
    VALUES (..., nextval('<table>_chain_seq'), hmac(prev_hash || canonical(data), secret));
COMMIT;
```

Write amplification при advisory lock: acceptable — audit writes
редкие относительно query reads, и lock scope ограничен одной
транзакцией (milliseconds). Если потребуется throughput optimization,
micro-batching (вместо per-row lock) — W3 design space.

**Failure modes**:
- INSERT fail (chain write): row не пишется. Caller получает error.
  Нет partial write.
- Chain_secret not set: enterprise build → startup failure. Core build
  → chain disabled (явно логируется как reduced-guarantee mode).
- Advisory lock contention: при высоком concurrent insert rate
  это serialization bottleneck. Acceptable для compliance audit trail
  (не hot-path для user-facing latency). Audit writes уже async-buffered.

### 7.3 Layer 2: Periodic Merkle anchor (W3 scope)

Scheduler каждые `AUDIT_ANCHOR_INTERVAL` (default: 1 hour):

1. Собирает все rows за предыдущий период.
2. Строит Merkle tree из row_hash'ей (canonical order by seq_no).
3. Записывает Merkle root + timestamp + row_count + table + epoch
   в `audit_anchor_log` (новая таблица).
4. Публикует root в configured sink:
   - `file://` — append-only local file (no external dependency, baseline).
   - `siem://` — через SIEM mirror (SIEM как secondary anchor).
   - `immudb://` — immudb self-hosted (strong immutable W3).
   - `s3://` — S3 Object Lock (cloud tier).
5. anchor_log entry включает sink_confirmation (success/failure) и
   sink_ref (URL, block hash, etc.).

**Verifier** (extended CLI):
```
audit-verify --include-anchors --anchor-sink file:///var/audit-anchors.log
  --row-id 550e8400-e29b-41d4-a716-446655440000
```
Доказывает inclusion в Merkle tree для конкретной row. Auditor может
проверить offline без доступа к БД.

### 7.4 Legal hold interaction (W2 scope — included)

Existing legal hold (PR-L2.3) уже обеспечивает retention-protection:
rows под active hold не purge'аются.

**Решение (review fix)**: `legal_holds` table включается в W2 chain
scope (не откладывается на W3+). Обоснование:

- `legal_holds` — enterprise-only table (PR-L2.3), W2 уже enterprise-only.
- Hold state machine (pending → active → released) с 4-eyes approval
  (PR-L2.3) IS compliance evidence — его mutable state в W2 без
  chain'а означает, что история одобрений/отзывов остаётся изменяемой
  именно в том периоде, когда chain уже работает для audit_logs.
- Low additional implementation cost: same seq_no + row_hash pattern,
  одна дополнительная таблица.

Chain / anchor для legal_holds добавляет:
- Hold state (`status`, `approved_by`, `approved_at`) включается в
  `row_hash` для каждой `legal_holds` mutation (create, approve, reject,
  release).
- Anchor log содержит count of active holds per epoch — auditor
  видит что hold существовал в момент anchor'а.
- Purge scheduler обязан писать в `audit_purge_runs` с chain entry
  ДО удаления. Purge без chain entry = compliance violation.

### 7.5 Backup/restore behavior

- **Restore-from-backup**: после restore последний chain tip известен.
  Verifier сравнивает с external anchor → если anchor содержит rows
  отсутствующие в restore → GAP_BY_RESTORE detected.
- **Pre-restore anchor**: перед любым restore оператор обязан
  запустить `audit-verify --snapshot` и сохранить результат.
  Runbook фиксирует этот протокол.

### 7.6 Clock skew / sequence ordering

- `seq_no` — primary ordering. `created_at` — human-readable, но
  не trust'ется для ordering в chain.
- Monotonic `SEQUENCE` в PG обеспечивает strict ordering per-table.
- Clock skew влияет только на `created_at` display, не на chain integrity.

### 7.7 Failure semantics when anchor sink unavailable

- SIEM-level SIEM fail-open already exists (PR-S1).
- Anchor sink unavailability:
  - `file://` (local) — очень редкий fail. Если disk full → audit write
    continues, anchor write fails, error logged, metric incremented.
  - `immudb://` — fail-open: row в PG пишется, anchor в immudb
    ставится в retry queue. Max retry_window configurable.
    Оператор alert'ится через `audit_anchor_fail_total` metric.
  - All sinks failing → anchor gap. Не блокирует audit writes.
    Gap будет visible при next verifier run.

---

## 8. Verification Model

### 8.1 What can be verified

| Claim                                | How verified              | Requires                       |
|--------------------------------------|---------------------------|--------------------------------|
| Row X was not modified               | Recompute row_hash        | chain_secret + row data        |
| No rows deleted between A and B      | seq_no continuity         | access to table (or verifier)  |
| Row X existed at epoch T             | Merkle proof from anchor  | anchor log + Merkle proof      |
| DB not restored to pre-T state       | post-T rows in anchor     | anchor log (external)          |
| Legal hold was active at epoch T     | anchor includes hold count | anchor log                    |

### 8.2 What can NOT be verified (remaining gaps, honest)

- Row was suppressed **before** reaching the DB (app-level interception).
  Mitigation: W2 chain starts at DB INSERT, not at application write.
  Application-level interception requires compromising app code + deploy
  simultaneously with DB — significantly harder attack surface.
- Anchor published to SIEM was retroactively modified by SIEM vendor.
  Mitigation: use two independent sinks or file:// + SIEM as redundancy.
- Chain secret leakage + full DB rewrite. Mitigation: key rotation
  (W3 design), HSM integration (W4 roadmap).

### 8.3 Operator verification procedure

```bash
# Daily automated run (CI/CD or cron):
audit-verify --table audit_logs --last 24h

# Before/after any admin operation:
audit-verify --snapshot > before.json
# ... perform operation ...
audit-verify --snapshot > after.json
diff before.json after.json

# Offline forensic audit (auditor with read-only access):
audit-verify --table admin_event_logs \
  --from 2026-01-01 --to 2026-04-23 \
  --anchor-sink file:///secure/anchors.log \
  --output report.json
```

### 8.4 Verification tiers (W2/W3/W4+)

Каждый tier даёт разный уровень offline verifiability. Это design
decision, зафиксированный RFC (review fix: устраняет inconsistency
между §8.4 и §11).

**W2 — Internal integrity verification (requires chain_secret):**
- Verifier использует тот же `AUDIT_CHAIN_SECRET`, что и signer.
  HMAC verification = shared-secret: нет технической возможности
  верифицировать без секрета.
- Scope: compliance team / security team — не внешний аудитор.
- Что detecteруется: chain break (row modification), seq_no gaps
  (row deletion).
- "Public HMAC" — некорректный термин, удалён.

**W3 — Gap detection without secret (via Merkle anchor):**
- Merkle root в anchor log не требует chain_secret для proof-of-inclusion.
- Внешний аудитор с anchor log + row export может:
  - Пересчитать Merkle tree из row_hash'ей.
  - Сравнить root с anchored root.
  - Обнаружить удалённые или добавленные rows (gap/addition).
- **Ограничение**: аудитор видит row_hash, но не может проверить
  соответствие hash → content без chain_secret. Он видит "rows
  пропали" или "появились лишние", но не "content был изменён" —
  для последнего нужен W4 asymmetric.

**W4+ — True third-party verification (asymmetric signing, Ed25519):**
- Signing key: private key (только app process / HSM).
  Verification key: public key (freely distributable).
- Аудитор НИКОГДА не получает signing secret — верифицирует
  с public key.
- Full content integrity + non-repudiation без secret sharing.
- Требует PKI infrastructure. Scope W4+.

**Summary table:**

| Tier  | Secret needed | Detects modification | Detects deletion | Third-party verifiable |
|-------|---------------|----------------------|------------------|------------------------|
| W2    | Yes           | Yes                  | Yes              | No (internal only)     |
| W3    | No            | No                   | Yes (gap)        | Partial (gaps only)    |
| W4+   | No            | Yes                  | Yes              | Yes (full)             |

---

## 9. Rollout Stages

### W1 (this RFC)

- RFC approval.
- Vocabulary aligned: what is "evidence", what are attacker models.
- Architecture locked: local chain + Merkle anchor + file sink baseline.
- No code changes.

### W2 — Minimal chain + verifier

Scope:
- `seq_no` и `row_hash` columns в следующих таблицах (migration):
  - `audit_logs` (core)
  - `admin_event_logs` (enterprise)
  - `legal_holds` (enterprise) — включено по review fix §7.4
- Chain write на INSERT — Go application layer + `pg_advisory_xact_lock`
  per-table (§7.2). Chain_secret в env var, never in DB.
- `audit_purge_runs` включает chain entry ДО purge.
- `cmd/audit-verify` CLI: seq_no gap detection + chain continuity.
  W2 verifier требует chain_secret (internal compliance только — §8.4).
- Enterprise-only. Core build без chain_secret = явный warning в startup.

Out of scope W2: Merkle anchor, external sink, Ed25519 asymmetric.

### W3 — Merkle anchor + external sink

Scope:
- `audit_anchor_log` table.
- Anchor scheduler (configurable interval).
- File sink baseline + immudb sink + SIEM sink.
- Extended verifier: Merkle inclusion proof.
- Backup/restore protocol in runbook.

### W3+ / W4 — WORM ledger + restore verification + audit tooling

Scope:
- Optional dual-write to immudb / S3 WORM для cloud tier.
- Key rotation для chain_secret.
- Automated restore verification hook.
- Auditor-facing dashboard / export tool.

---

## 10. Open Questions

### Разрешить до W2 implementation kickoff:

1. **Chain write serialization**: RESOLVED в §7.2 — `pg_advisory_xact_lock`
   per-table. Row hash вычисляется в Go application layer (секрет в memory,
   не в DB) после получения advisory lock и до INSERT. Конкурентность
   сериализуется на DB-уровне.

2. **Canonical row serialization spec**: JSON (deterministic field order)?
   Protocol Buffers? Simple concatenation of typed fields? **Recommendation**:
   custom fixed-field concatenation (strings left-padded, fixed-width where
   possible) — минимально зависит от JSON library implementation differences.

3. **chain_secret rotation policy**: при ротации нужно либо re-hash все
   существующие rows (expensive), либо поддерживать multiple active secrets
   с versioned prefix на row_hash. **Recommendation**: версионированный prefix
   ("v1:hash"), при ротации старые rows остаются с v1, новые с v2.
   Verifier знает оба секрета (key material management = W3 scope).

4. **anchor_interval default**: 1 hour даёт максимальный window где rows
   могут быть удалены без external anchor detection. Для compliance-heavy
   deploy может быть недостаточно. **Recommendation**: default 1h, configurable
   вплоть до 5min. Очень малый interval создаёт write amplification на anchor log.

5. **immudb vs другой self-hosted WORM**: immudb (opensource, Go, native
   gRPC) выглядит наиболее зрелым self-hosted вариантом. Финальный выбор
   фиксируется в W3 design, не здесь.

---

## 11. Security Considerations

- **chain_secret в env var**: аналогично `JWT_SECRET` и
  `LEGAL_HOLD_TOKEN_SECRET` — требует `>=32 chars` validation в
  `ValidateStartupConfig` (enterprise build).
- **chain_secret не в DB**: если chain_secret хранится в БД, DBA с
  DB-доступом может его прочитать и re-sign rows. Строго: secret in
  app process memory / secrets manager only.
- **HMAC-SHA256**: достаточен для W2/W3. При key rotation и при
  compromise — W3 key rotation protocol закрывает. Asymmetric (Ed25519
  signing) рассматривается для W4 — даёт non-repudiation без shared
  secret, но требует PKI infrastructure.
- **seq_no race**: PostgreSQL SEQUENCE atomic. Application не должна
  pre-allocate seq_no — он назначается сервером при INSERT.
- **Verifier access**: verifier CLI использует ТОТЖЕ `AUDIT_CHAIN_SECRET`
  что и signer (HMAC = shared secret; верификация без секрета невозможна
  в W2 — см. §8.4 verification tiers). Следствие: verifier CLI —
  привилегированный инструмент, доступ должен быть ограничен compliance/
  security team и auditеd через `admin_event_logs`. True third-party
  verification (без secret) — W4+ с Ed25519.
- **Legal hold rows в chain (W2 scope)**: `legal_holds` включена
  в W2 chain scope (см. §7.4). hold mutation (create/approve/reject/
  release) порождает chain entry — hold state history tamper-evident
  с той же гарантией, что audit_logs и admin_event_logs, с W2.

---

## 12. Acceptance Criteria for this RFC (W1)

1. ✅ Один чёткий recommended architecture path (Layer 1 → 2 → 3).
2. ✅ Explicit rejection of weaker alternatives (§6 с Verdict).
3. ✅ Staged rollout W1 → W2 → W3 → W4 (§9).
4. ✅ Threat model с явным scope (§3).
5. ✅ Hard invariants (§4).
6. ✅ После approval можно открывать W2 без повторной базовой дискуссии.

---

## 13. Implementation PRs

| PR  | Содержание                                                                  |
|-----|-----------------------------------------------------------------------------|
| W1  | Этот RFC                                                                    |
| W2  | `seq_no` + `row_hash` columns, chain write on INSERT, `cmd/audit-verify`   |
| W3  | `audit_anchor_log`, anchor scheduler, file/SIEM/immudb sinks, extended CLI |
| W4  | WORM ledger integration, key rotation, restore verification automation      |

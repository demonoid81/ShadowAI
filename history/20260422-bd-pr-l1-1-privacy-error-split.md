# PR-L1.1: Legal hold privacy + error-path split

## Контекст
Review PR-L1 выявил два medium-severity замечания:

1. **Privacy leak**: `case_ref` (internal legal identifier, e.g.
   `SEC-INTERNAL-2026-SECRET-42`) писался в `admin_event_logs` и
   через PR-S1 fan-out зеркалировался в SIEM. SIEM — это
   external evidence stream; matter-level identifier не должен
   там оказываться без необходимости.

2. **Error-path mixing**: `legalhold.Handler.Create` валил всё
   (кроме `already_active` / `not configured`) в HTTP 400 +
   `err.Error()`. Runtime/repo failures уходили клиенту как
   `400 {"error":"legalhold: insert: pq: ..."}` — неверные HTTP
   semantics + disclosure internal details.

PR-L1.1 закрывает оба. Мелкий фоллоу-ап, не затрагивает core
архитектуру enforcement.

## Scope (In)

### 1. `case_ref_hash` вместо raw `case_ref`
- Новая utility `caseRefHash(string) string` в `handler.go`:
  truncated SHA-256 (первые 8 байт → 16 hex chars = 64 bit).
- Используется в admin-event metadata для:
  - `apply_hold` success path
  - `apply_hold` conflict (409) path
  - `release_hold` success path
- Raw `case_ref` остаётся только в PG `legal_holds.case_ref`
  (admin получает через `GET /api/legal-holds`) и в response
  body `POST /legal-holds` (отдаётся тому же admin, что прислал
  его в request).
- SIEM mirror (PR-S1 fan-out) получает только hash — SIEM-rule'ы
  могут correlate events по `case_ref_hash`, но не читать сам
  reference.

### 2. Sentinel errors + handler split
- Новые sentinels в `service.go`:
  - `ErrValidation` — missing/empty fields.
  - `ErrNotConfigured` — nil service/repo.
- Existing: `ErrAlreadyActive`, `ErrNotActive`, `ErrNotFound`.
- Helpers: `IsValidation(err)`, `IsNotConfigured(err)`.
- `Service.CreateHold` / `ReleaseHold` / `HasActiveHold` / `List`
  возвращают типизированные errors вместо raw строк.
- `Handler.Create` / `Release` / `List` маршрутизируют по
  sentinels:
  - `ErrAlreadyActive` → 409 + `{error_code: already_active}`.
  - `ErrValidation` → 400 + generic `"invalid request"`.
  - `ErrNotConfigured` → 503 + generic `"legal hold not configured"`.
  - `ErrNotFound` (release) → 404 + `{error_code: not_found}`.
  - `ErrNotActive` (release) → 200 + `{status: already_released}`
    (idempotent).
  - default (repo/runtime) → 500 + generic
    `"hold creation failed"` / `"hold release failed"` / `"internal"`.
- admin-event metadata использует `error_code` (machine-readable):
  `already_active`, `validation_failed`, `not_configured`,
  `not_found`, `internal_error`.
- Legacy ключ `"error"` с raw строкой больше не пишется.

## Scope (Out)
- Structured logging с error context (v2; сейчас internal errors
  идут в stderr через `adminaudit.Service.Record` fail-open
  logger).
- Тот же split для других enterprise handler'ов (governance,
  adminaudit) — пока не требовалось ревью; применим если
  появится аналогичный complaint.

## Тесты (6 новых, 18 существующих не сломаны)

- `TestCreate_MetadataHasHashNotRawCaseRef` — regression guard:
  raw case_ref не попадает ни под одним ключом в metadata,
  `case_ref_hash` — 16 hex chars.
- `TestCreate_ConflictEventHasHashNotRawCaseRef` — то же для 409
  path (conflict event тоже не leak'ает raw).
- `TestCreate_ValidationError_GenericMessage` — response НЕ
  содержит `"legalhold:"` prefix; metadata содержит
  `error_code: validation_failed`, нет legacy `error` key.
- `TestCreate_NotConfigured_Returns503` — nil repo Service
  возвращает 503 с `error_code: not_configured`.
- `TestRelease_HappyPath_MetadataHasHashOnly` — release event
  тоже без raw case_ref.
- `TestCaseRefHash_Deterministic` — одинаковый input → одинаковый
  hash (для SIEM correlation); разные inputs → разные hashes.

Итого 24 теста в пакете, все зелёные. `go test ./...` +
`go test -tags enterprise ./...` — full matrix green.

## Acceptance criteria
- [x] `case_ref` не появляется в `admin_event_logs.metadata` ни в
      одном code path (success, conflict, release).
- [x] `case_ref_hash` присутствует для корреляции (SIEM rules).
- [x] Client НЕ получает raw internal `err.Error()` в HTTP response.
- [x] Validation / runtime / not-configured — разные HTTP codes
      (400 / 500 / 503).
- [x] Admin-event metadata содержит machine-readable `error_code`.
- [x] Core + enterprise builds green; regression matrix green.

## Примеры before/after

### Before (PR-L1)
**Response на validation error:**
```json
HTTP 400 Bad Request
{"error":"legalhold: case_ref required"}
```
**Response на repo error:**
```json
HTTP 400 Bad Request
{"error":"legalhold: insert: pq: connection refused"}
```
**admin_event on apply success:**
```json
{"metadata":{"target_user_id":"u-1","case_ref":"SEC-INTERNAL-2026-SECRET-42"}}
```
(raw case_ref leak'ает в SIEM mirror)

### After (PR-L1.1)
**Response на validation error:**
```json
HTTP 400 Bad Request
{"error":"invalid request"}
```
**Response на repo error:**
```json
HTTP 500 Internal Server Error
{"error":"hold creation failed"}
```
**admin_event on apply success:**
```json
{"metadata":{"target_user_id":"u-1","case_ref_hash":"a4f2b91c3d5e8f02"}}
```
(SIEM видит только hash, raw остаётся в legal_holds.case_ref)

## Риски / допущения
- **Hash truncation collision**: 64 bit collision space ≈ 4.3B.
  Для SIEM correlation (единицы-десятки active cases в год)
  collision вероятность негligible. Если когда-то потребуется —
  увеличить до full 32-byte (hex 64).
- **Compatibility**: existing SIEM rules, опирающиеся на
  `case_ref` field в admin_event_logs, сломаются. Нужна migration
  note в release: `case_ref` → `case_ref_hash`.
- **Forensic recovery**: у operator'а есть pipeline
  "случилось X, найти hold" через SIEM correlation по hash —
  достаточно: взять hash → найти hold_id в SIEM → посмотреть в
  PG `legal_holds WHERE id = hold_id` для raw case_ref.

## History
- Plan: этот файл.
- Related: PR-L1 (legal hold groundwork).

## Next roadmap (без изменений)
1. SIEM v1.1 (syslog/OTel/batching).
2. Legal hold v2 (retention-aware purge, 4-eyes, query scope).
3. G2 role-based governance.
4. WORM primary.
5. Firewall/runtime track.

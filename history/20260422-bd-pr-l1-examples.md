# PR-L1 Examples

Сценарии поведения legal hold в разных условиях.

## Happy paths (3)

### Example 1: Apply hold → blocked erase → release → successful erase

**Setup:** enterprise build + migration 013 applied.

**Step 1 — apply hold:**
```http
POST /api/legal-holds
Authorization: Bearer <admin-jwt>
Content-Type: application/json

{
  "target_user_id": "u-target",
  "case_ref": "SEC-2026-042",
  "reason": "SEC inquiry per LEGAL-137 ticket"
}
```
**Response 201:**
```json
{
  "id": "h-abc123",
  "target_user_id": "u-target",
  "case_ref": "SEC-2026-042",
  "reason": "SEC inquiry per LEGAL-137 ticket",
  "created_by": "u-admin",
  "created_at": "2026-04-22T14:30:00Z",
  "is_active": true
}
```
**admin_event_logs + SIEM:**
```json
{
  "action": "apply_hold",
  "resource": "legal_hold",
  "target_id": "h-abc123",
  "success": true,
  "metadata": {"target_user_id":"u-target","case_ref":"SEC-2026-042"}
}
```

**Step 2 — DSAR попытка:**
```http
POST /api/users/u-target/erase
Authorization: Bearer <admin-jwt>
```
**Response 409:**
```json
{"user_id":"u-target", "status":"hold_active"}
```
**admin_event_logs + SIEM:**
```json
{
  "action": "erase",
  "resource": "user",
  "target_id": "u-target",
  "status_code": 409,
  "success": false,
  "metadata": {
    "status": "hold_active",
    "blocked_by_hold": true,
    "audit_rows_scrubbed": 0,
    "budgets_deleted": 0
  }
}
```

**Step 3 — release:**
```http
POST /api/legal-holds/h-abc123/release
Authorization: Bearer <admin-jwt>
```
**Response 200:**
```json
{
  "id": "h-abc123",
  "target_user_id": "u-target",
  "case_ref": "SEC-2026-042",
  "released_by": "u-admin",
  "released_at": "2026-05-15T09:00:00Z",
  "is_active": false
}
```

**Step 4 — retry DSAR:**
```http
POST /api/users/u-target/erase
```
**Response 200:**
```json
{
  "user_id": "u-target",
  "status": "completed",
  "audit_rows_scrubbed": 127,
  "budgets_deleted": 1
}
```

### Example 2: Duplicate apply — 409

```http
POST /api/legal-holds
{ "target_user_id": "u-target", "case_ref": "LEG-2", "reason": "..." }
```
(user уже под active hold из Example 1).

**Response 409:**
```json
{"error": "user already has active hold"}
```
**admin_event:** `apply_hold` с `success=false, metadata.error=already_active`.

### Example 3: Idempotent release

Release того же hold дважды:

**First release:** 200 с полным hold-response (Example 1 Step 3).
**Second release:**
```json
{"id": "h-abc123", "status": "already_released"}
```
200 (не 404), чтобы replay-safe operator scripts не падали.

## Edge cases (3)

### Example 4: Release на несуществующий id — 404

```http
POST /api/legal-holds/h-missing/release
```
**Response 404:** `{"error":"hold not found"}`. Event с `success=false`.

### Example 5: Non-admin пытается apply — 403

User с role=user делает:
```http
POST /api/legal-holds
```
**Response 403:** `{"error":"forbidden"}`. Event НЕ пишется
(middleware отверг до handler'а) — это acceptable для v1;
higher-security setups могут добавить logging на middleware-level.

### Example 6: Create после release на того же user — OK

Released holds не блокируют новые applies для того же user'а.
Partial-unique index в PG действует только на `is_active=true`.
Сценарий: recurring litigation, cycles apply → release → apply.

История в `GET /api/legal-holds`:
```json
[
  {"id":"h-new","target_user_id":"u-target","is_active":true,...},
  {"id":"h-abc123","target_user_id":"u-target","is_active":false,
   "released_at":"2026-05-15T09:00:00Z",...}
]
```
Active first, released после — operator видит полную историю.

## Failure cases (2)

### Example 7: legal_holds таблица отсутствует (missing migration)

**Setup:** enterprise build запущен, но migration 013 забыли
применить. `HasActiveHold` получит PG error (relation does not
exist).

**EraseUser behavior (fail-closed):**
```http
POST /api/users/u-target/erase
```
**Response 500:** `{"error":"erasure failed"}`.
**admin_event:** `erase` с `success=false, metadata.error="erasure failed"`.

Оператор видит 500 в логах, grep'ит `erasure: hold check:` в stderr —
сразу понимает что migration pending. Compliance-safe: erase НЕ
выполнен, user данные на месте.

### Example 8: Core build — legal holds endpoints не существуют

```bash
go build ./cmd/shadowai   # без -tags enterprise
./shadowai &

curl http://localhost:8080/api/legal-holds
# → 404 page not found
```

В Core-build `legalhold` пакет не слинкован, routes не
регистрируются в `enterprise_stubs.go` (`RegisterRoutes = no-op`).
Это acceptable: operator Core-билда не имеет compliance-контроля,
но и не думает что имеет (нет endpoints).

## SIEM-side forensic queries

После PR-L1 в SIEM поверх `stream=admin_event_logs` можно строить:

### Все попытки erase held user'ов
```sql
SELECT actor_user_id, target_id AS blocked_user, created_at,
       metadata->>'status' AS status
FROM admin_event_logs
WHERE resource='user' AND action='erase'
  AND (metadata->>'blocked_by_hold')::bool = true
ORDER BY created_at DESC;
```
Это evidence «DSAR requests на held users правильно блокируются» —
прямо то, что хочет аудитор.

### Активные holds старше 90 дней
```sql
SELECT target_id AS hold_id,
       metadata->>'target_user_id' AS user_id,
       metadata->>'case_ref' AS case_ref,
       created_at
FROM admin_event_logs
WHERE resource='legal_hold' AND action='apply_hold'
  AND success=true
  AND created_at < now() - interval '90 days'
  AND NOT EXISTS (
    SELECT 1 FROM admin_event_logs r
    WHERE r.resource='legal_hold' AND r.action='release_hold'
      AND r.target_id = admin_event_logs.target_id
  );
```
Hold-hygiene check: long-standing holds которые никто не release'ил.
Может требовать escalation в legal.

### Duplicate apply attempts (suspicious)
```sql
SELECT actor_user_id, metadata->>'target_user_id' AS user_id, COUNT(*)
FROM admin_event_logs
WHERE resource='legal_hold' AND action='apply_hold' AND success=false
  AND metadata->>'error' = 'already_active'
GROUP BY actor_user_id, user_id
HAVING COUNT(*) > 3;
```
«Admin пытался apply hold на уже-held user больше 3 раз» — признак
misconfigured automation или coordinated confusion.

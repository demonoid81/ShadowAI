# PR-G0.1 Examples

Сценарии поведения ListUsers access audit в разных условиях.

## Happy paths (2)

### Example 1: Admin вызывает GET /api/users, 3 user'а в БД

**Request:**
```http
GET /api/users HTTP/1.1
Authorization: Bearer <admin-jwt>
```

**Response (200 OK):**
```json
[
  {"id":"u-1","email":"alice@co.com","role":"admin",...},
  {"id":"u-2","email":"bob@co.com","role":"user",...},
  {"id":"u-3","email":"carol@co.com","role":"analyst",...}
]
```

**admin_event_logs insert:**
```json
{
  "actor_user_id": "u-admin",
  "action": "list",
  "resource": "users",
  "target_id": "",
  "path": "/api/users",
  "method": "GET",
  "status_code": 200,
  "success": true,
  "metadata": {"user_count": 3}
}
```

Email'ы/role'ы в event НЕ дублируются — они уже в response.
SIEM-правило может заалертить при `user_count > 100` как признак
bulk-exfiltration attempt.

### Example 2: Empty DB (нет пользователей)

**Request:** `GET /api/users` от admin.

**Response:** `[]`

**admin_event_logs insert:**
```json
{
  "action": "list",
  "resource": "users",
  "success": true,
  "metadata": {"user_count": 0}
}
```

Event всё равно пишется — это штатное событие, просто с
`user_count=0`.

## Edge cases (2)

### Example 3: Core build (nil adminAudit)

`go build ./cmd/shadowai` (без `-tags enterprise`).

**Request:** `GET /api/users`.
**Response:** `[...]` (200, normal).
**admin_event_logs:** таблица не существует (migration 010 не
применён в Core-scope). `h.adminAudit=nil` → `recordUsersList`
no-op.

Ни panic, ни error. Core-build работает без enterprise-trail.

### Example 4: Unauthenticated edge case

Middleware не прикрепил claims (например, internal call минуя auth).

**Request:** `GET /api/users` без JWT.
**Observed state:** `GetClaims(ctx)` возвращает nil.

**admin_event_logs insert:**
```json
{
  "actor_user_id": null,
  "action": "list",
  "resource": "users",
  "success": false,
  "metadata": null
}
```

Actor=null — сам факт `forensic signal`. SIEM-правило может поднять
alert на любое событие с `actor_user_id IS NULL AND action='list'`
(это не должно случаться в штатной конфигурации).

## Failure case (1)

### Example 5: PG недоступна → ListUsers возвращает 500

**Setup:** DB connection dropped, `service.GetRepo().ListUsers`
возвращает err.

**Request:** `GET /api/users`.

**Response (500):**
```json
{"error": "internal server error"}
```

**admin_event_logs insert (попытка):**
```json
{
  "actor_user_id": "u-admin",
  "action": "list",
  "resource": "users",
  "status_code": 500,
  "success": false,
  "metadata": {"error": "repo_failure"}
}
```

Если PG всё ещё недоступна, admin event тоже не запишется
(adminaudit.Service fail-open — логирует в stderr, не паникует).
Это acceptable: primary endpoint уже failed, forensic-trail
лучшего уровня чем "nothing" — в stderr logs хоста.

## SIEM rule examples

Полезные запросы поверх этих событий:

### Bulk read detection
```sql
SELECT actor_user_id, COUNT(*) AS list_scans,
       MAX((metadata->>'user_count')::int) AS largest_scan
FROM admin_event_logs
WHERE action='list' AND resource='users'
  AND created_at > now() - interval '1 day'
GROUP BY actor_user_id
HAVING COUNT(*) > 10
ORDER BY list_scans DESC;
```
«Какие admin'ы за сутки более 10 раз подняли user-list»
(признак подозрительной активности — UI не требует такого refresh rate).

### Bulk exfiltration pattern
```sql
SELECT actor_user_id, created_at,
       (metadata->>'user_count')::int AS count
FROM admin_event_logs
WHERE action='list' AND resource='users'
  AND (metadata->>'user_count')::int > 1000;
```
«Кто когда-то подгружал >1000 пользователей за один запрос».

### Failed access attempts
```sql
SELECT actor_user_id, status_code, metadata->>'error' AS err, created_at
FROM admin_event_logs
WHERE resource='users' AND success=false
ORDER BY created_at DESC LIMIT 50;
```
«Последние 50 failed list-доступов» — может помочь в root-cause DB
incidents или выявлении злоупотреблений.

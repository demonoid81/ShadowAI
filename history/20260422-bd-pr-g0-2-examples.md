# PR-G0.2 Examples

Сценарии UpdateUser access audit + форматы metadata.

## Happy paths (2)

### Example 1: Role change (user → admin)

**Before in DB:**
```
id=u-target, email="bob@co.com", role="user", is_active=true
```

**Request:**
```http
PUT /api/users/u-target
Authorization: Bearer <admin-jwt>
Content-Type: application/json

{"role": "admin"}
```

**Response (200 OK):**
```json
{"id":"u-target","email":"bob@co.com","role":"admin","is_active":true}
```

**admin_event_logs insert:**
```json
{
  "actor_user_id": "u-admin",
  "action": "update",
  "resource": "user",
  "target_id": "u-target",
  "path": "/api/users/u-target",
  "method": "PUT",
  "status_code": 200,
  "success": true,
  "metadata": {
    "changed_fields": ["role"],
    "old_role": "user",
    "new_role": "admin"
  }
}
```

Privileges escalation видна сразу: `changed_fields` содержит `role`,
`old_role → new_role`. SIEM может поднять ALERT при любом
`new_role = "admin"`.

### Example 2: Deactivation + email fix одной PUT-операцией

**Before:**
```
id=u-target, email="old@co.com", role="user", is_active=true
```

**Request:** `{"email": "new@co.com", "is_active": false}`.

**admin_event_logs insert:**
```json
{
  "action": "update",
  "resource": "user",
  "target_id": "u-target",
  "success": true,
  "metadata": {
    "changed_fields": ["email", "is_active"],
    "email_changed": true,
    "old_email_empty": false,
    "old_is_active": true,
    "new_is_active": false
  }
}
```

Email-значения **НЕ пишутся** — только факт изменения. `is_active`
diff пишется полностью (boolean — не PII).

## Edge cases (2)

### Example 3: No-op PUT (те же значения)

**Before:** `role="user"`, `is_active=true`, `email="bob@co.com"`.
**Request:** `{"role": "user", "email": "bob@co.com"}`.

**admin_event_logs insert:**
```json
{
  "action": "update", "resource": "user", "target_id": "u-target",
  "success": true,
  "metadata": {
    "changed_fields": []
  }
}
```

`changed_fields` пустой — это штатное событие, но forensics видит:
«admin коснулся этого user'а, хоть и ничего не изменил». Для
high-sensitivity compliance контекста это важная информация.

### Example 4: Core build (nil adminAudit)

`go build ./cmd/shadowai` (без `-tags enterprise`).

**Request:** `PUT /api/users/u-target` c `{"role":"admin"}`.
**Response:** 200 с обновлённым user (update в БД прошёл).
**admin_event_logs:** не пишется (таблицы нет / h.adminAudit=nil).

Core-build не имеет admin-audit trail — это acceptable (ENTERPRISE.md
явно указывает retention/audit как enterprise scope).

## Failure paths (4)

### Example 5: 404 Not Found

**Request:** `PUT /api/users/u-missing` c любым body.
**Response:** `{"error": "user not found"}` (404).

**admin_event_logs insert:**
```json
{
  "action": "update", "resource": "user", "target_id": "u-missing",
  "status_code": 404, "success": false,
  "metadata": {"error": "user not found"}
}
```

Event пишется даже на 404 — forensics: «admin пытался изменить
несуществующего user'а» — может быть признаком stale UI state или
подозрительного scanning.

### Example 6: 400 Invalid role

**Request:** `PUT /api/users/u-target` c `{"role": "superking"}`.
**Response:** `{"error": "invalid role"}` (400).

**admin_event_logs insert:**
```json
{
  "success": false, "status_code": 400,
  "metadata": {
    "error": "invalid_role",
    "attempted_role": "superking"
  }
}
```

`attempted_role` — **raw**, не normalized. SIEM может детектить:
- typo (`"amdin"`, `"usr"`) — UX issue;
- injection attempt (`"admin OR 1=1"`) — security signal;
- попытки неподдерживаемых roles (`"superking"`, `"god"`) —
  подозрительная активность.

### Example 7: 400 Invalid JSON

**Request:** body = `"not valid json"`.
**Response:** 400 invalid request body.

**admin_event_logs insert:**
```json
{
  "success": false, "status_code": 400,
  "metadata": {"error": "invalid_json"}
}
```

Не паникует, не утекает body в logs. Event всё равно записан.

### Example 8: 500 Repo failure

**Setup:** DB connection drop / deadlock.

**admin_event_logs insert (попытка, тоже может fail):**
```json
{
  "success": false, "status_code": 500,
  "metadata": {"error": "repo_failure"}
}
```

Fail-open: если admin_event_logs INSERT тоже провалится
(adminaudit.Service fail-opens), логгер stderr получит запись.

## SIEM rule examples

### Privilege escalation alert
```sql
SELECT actor_user_id, target_id,
       metadata->>'old_role' AS old, metadata->>'new_role' AS new,
       created_at
FROM admin_event_logs
WHERE action='update' AND resource='user'
  AND metadata->>'new_role' = 'admin'
  AND metadata->>'old_role' != 'admin'
ORDER BY created_at DESC;
```
«Все случаи, когда кого-то впервые сделали admin'ом».

### Mass bulk deactivations
```sql
SELECT actor_user_id, COUNT(*) AS deactivations
FROM admin_event_logs
WHERE action='update' AND resource='user'
  AND metadata->>'new_is_active' = 'false'
  AND created_at > now() - interval '1 hour'
GROUP BY actor_user_id
HAVING COUNT(*) > 5;
```
«Какой admin за час деактивировал более 5 юзеров» (признак inside
threat или compromised admin-account).

### Invalid role attempts (typo vs injection)
```sql
SELECT actor_user_id, metadata->>'attempted_role' AS attempted,
       created_at
FROM admin_event_logs
WHERE action='update' AND resource='user'
  AND metadata->>'error' = 'invalid_role'
  AND metadata->>'attempted_role' ~ '[^a-zA-Z_]'
ORDER BY created_at DESC;
```
«Попытки ввести роль с символами кроме букв/подчёркивания» —
candidate для injection-отработки.

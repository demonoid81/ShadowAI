# PR-S1 Examples

Сценарии поведения SIEM mirror в разных условиях.

## Happy paths (2)

### Example 1: Admin читает user list → event уходит в SIEM

**Setup:**
```
SIEM_ENABLED=true
SIEM_ENDPOINT=https://siem.example.com/ingest
SIEM_BEARER_TOKEN=splunk-hec-xxx
```

**Request:** `GET /api/users` от admin.
**Response:** 200 OK + user list.

**admin_event_logs (PG):**
```sql
SELECT action, resource, metadata FROM admin_event_logs ORDER BY created_at DESC LIMIT 1;
-- action=list resource=users metadata={"user_count":15}
```

**SIEM HTTP POST:**
```http
POST https://siem.example.com/ingest
Content-Type: application/json
Authorization: Bearer splunk-hec-xxx

{
  "source": "shadowai",
  "stream": "admin_event_logs",
  "event": {
    "actor_user_id": "u-admin",
    "action": "list",
    "resource": "users",
    "path": "/api/users",
    "method": "GET",
    "status_code": 200,
    "success": true,
    "metadata": {"user_count": 15},
    "created_at": "2026-04-22T14:30:12.123456Z"
  }
}
```

**Metrics:**
```
shadowai_siem_requests_total{sink="http"} +1
shadowai_siem_latency_seconds{sink="http"} observe 0.042
```

### Example 2: Disabled mode (bootstrap / self-host без external SIEM)

**Setup:** `SIEM_ENABLED=false` (default).

**Request:** `GET /api/users`.
**Response:** 200 OK.

**admin_event_logs:** записано как обычно.
**SIEM:** никаких network calls. `adminAuditRecorder == adminAuditSvc`
напрямую (без fanout).
**Metrics:** `shadowai_siem_requests_total` остаётся 0.

Это дефолтный state. Enterprise деплой может годами работать без
SIEM, потом легко включить через env-флаг без code change.

## Edge cases (3)

### Example 3: Core build (без `-tags enterprise`)

SIEM-пакета в бинарнике нет. Даже если operator случайно выставит
`SIEM_ENABLED=true`, никакого эффекта: `enterprise_stubs.go`
возвращает bundle с `AdminAudit=nil`, и handlers просто не пишут
admin events. HTTP recorder не существует as compiled code.

Это защищает Core-only operator'а от "полуоткрытого" state (env
включён, но реализация отсутствует).

### Example 4: Invalid/empty endpoint при SIEM_ENABLED=true

**Setup:** `SIEM_ENABLED=true`, `SIEM_ENDPOINT=""`.

**Behavior:** В `enterprise_wire.go` проверка:
```go
if deps.Cfg.SIEMEnabled && deps.Cfg.SIEMEndpoint != "" {
    // wrap with fanout
}
```

Если endpoint пустой → fanout НЕ создаётся, adminAuditRecorder
остаётся `adminAuditSvc`. Effectively SIEM off despite env flag.
Operator увидит, что `shadowai_siem_requests_total` == 0 — это
health signal: "настройка не применилась".

### Example 5: Bearer token не задан

**Setup:** endpoint работает без auth (internal network, allowlist
по source IP).

**Behavior:** `SIEM_BEARER_TOKEN=""` → Authorization header
НЕ добавляется. HTTP POST без auth header — если sink требует
auth, он вернёт 401, что увеличит `shadowai_siem_fail_total`.

## Failure cases (3)

### Example 6: Sink возвращает 500

**Observed:** `srv.ServeHTTP` возвращает 500 Internal Server Error.

**Behavior:**
- Primary admin endpoint (например, `GET /api/users`) отвечает
  200 как обычно.
- PG write прошёл.
- SIEM write получил 500.
- `shadowai_siem_fail_total{sink="http"} +1`.
- Local log: `siem: non-2xx endpoint=siem.example.com action=list status=500`.
- Operator'у алерт через Prometheus: `rate(shadowai_siem_fail_total[5m]) > 0`.

### Example 7: Sink timeout

**Setup:** sink отвечает через 10 секунд, `SIEM_TIMEOUT=3s`.

**Behavior:**
- `context.DeadlineExceeded` через 3s.
- `shadowai_siem_timeout_total{sink="http"} +1`.
- Local log: `siem: timeout endpoint=siem.example.com action=list`.
- Primary endpoint вернулся с latency +3s (acceptable для v1;
  v1.1 async queue уберёт это).

### Example 8: Network partition

**Setup:** SIEM endpoint полностью недоступен (DNS fail / TCP
connection refused).

**Behavior:**
- `err` non-nil, НЕ timeout → `shadowai_siem_fail_total +1`.
- Local log: `siem: post failed endpoint=... err=dial tcp: lookup siem.example.com: no such host`.
- PG write остаётся source of truth — operator может позже replay
  через external script (`pg_dump admin_event_logs | external-forwarder`).

## SIEM-side rules

После включения PR-S1 у operator'а в SIEM можно строить правила
поверх `stream=admin_event_logs`:

### Splunk SPL
```
source="shadowai" stream="admin_event_logs" event.action="erase" 
| stats count by event.actor_user_id
| where count > 5
```
«Admin-аккаунт выполнил более 5 erase-операций» — подозрительно.

### Elastic KQL
```
source:"shadowai" AND stream:"admin_event_logs"
AND event.success:false AND event.resource:"user"
AND event.metadata.error:"invalid_role"
```
«Все failed role-change attempts» — input validation failures,
возможно признак misconfigured integration или injection.

### Sigma-style rule (vendor-neutral)
```yaml
title: ShadowAI Privilege Escalation
logsource:
  product: shadowai
  service: admin_event_logs
detection:
  selection:
    event.action: update
    event.resource: user
    event.metadata.new_role: admin
  condition: selection
level: high
```

## Config matrix

| SIEM_ENABLED | SIEM_ENDPOINT | Build | Behavior |
|---|---|---|---|
| `false` (default) | any | any | SIEM off, только PG |
| `true` | `""` | any | SIEM off (invalid config), только PG |
| `true` | `https://...` | Core | SIEM off (package not compiled) |
| `true` | `https://...` | Enterprise | SIEM on, fanout active |

## Rollback

Если SIEM integration начинает влиять на primary endpoint latency:
```bash
# Hot rollback: просто выключить env flag и restart.
export SIEM_ENABLED=false
systemctl restart shadowai
```
После restart fanout не создаётся; все admin events пишутся только
в PG. Zero code change.

# PR-L2.3 — примеры (happy / edge / failure)

Формат: request → expected response + side effects (repo state,
admin events). Admin token подразумевается — `Authorization` опущен
для краткости.

---

## Пример 1 (happy): полный 4-eyes flow

### 1.1 Create pending (creator=u-alice)

```
POST /api/legal-holds
{"target_user_id":"u-target","case_ref":"SEC-2026-042","reason":"SEC inquiry LEGAL-137"}
```

**Response 201:**
```json
{
  "id": "h-123",
  "target_user_id": "u-target",
  "case_ref": "SEC-2026-042",
  "reason": "SEC inquiry LEGAL-137",
  "status": "pending",
  "created_by": "u-alice",
  "created_at": "2026-04-22T20:00:00Z",
  "is_active": false
}
```

**Side effects:**
- `legal_holds` row: status=pending, is_active=false, approved_at/by NULL.
- `admin_event_logs`: action=apply_hold_requested, success=true,
  metadata: `{target_user_id:"u-target", case_ref_hash:"<16hex>", status:"pending"}`.
- SIEM mirror: тот же event.
- **DSAR на u-target не блокируется**: `POST /api/users/u-target/erase` → 200 erased.

### 1.2 Approve (approver=u-bob, другой admin)

```
POST /api/legal-holds/h-123/approve
```

**Response 200:**
```json
{
  "id": "h-123",
  "status": "active",
  "approved_at": "2026-04-22T20:05:00Z",
  "approved_by": "u-bob",
  "is_active": true,
  ...
}
```

**Side effects:**
- `legal_holds` row: status=active, is_active=true, approved_at/by set.
- `admin_event_logs`: action=apply_hold_approved, success=true,
  metadata: `{..., status:"active"}`.
- **DSAR теперь блокируется**: `POST /api/users/u-target/erase` → 409 `{status:"hold_active"}`.
- Retention-aware purge исключает audit_logs для u-target.

### 1.3 Release после litigation закончен

```
POST /api/legal-holds/h-123/release
```

**Response 200**: status=released, released_at/by set.
Event release_hold.

---

## Пример 2 (edge): self-approval blocked

### 2.1 Create (creator=u-alice)

Как в Примере 1.1. status=pending.

### 2.2 u-alice пытается approve собственный hold

```
POST /api/legal-holds/h-123/approve     (token=u-alice)
```

**Response 403:**
```json
{"error": "approver must differ from creator"}
```

**Side effects:**
- `legal_holds` row: UNCHANGED (status все ещё pending).
- `admin_event_logs`: action=apply_hold_approved, success=false,
  status_code=403, metadata:
  `{error_code:"self_approval"}`.
- SIEM mirror получает тот же event — это **критичный signal**
  для alerting: admin пытается обойти 4-eyes.

### 2.3 Исправление

Другой admin (u-bob) делает approve → всё работает штатно.
Если only-one-admin deploy — compliance violation, документируется
в Runbook §5.3 как организационное требование.

---

## Пример 3 (edge): reject cancels own request

### 3.1 Create (creator=u-alice)

status=pending.

### 3.2 u-alice reject'ит собственный request (cancel)

```
POST /api/legal-holds/h-123/reject     (token=u-alice)
```

**Response 200**: status=released, released_by=u-alice.
Event apply_hold_rejected success=true.

**Side effects:**
- Hold больше не blocking в partial-unique index → можно создать
  новый pending на u-target.
- DSAR работает штатно (status != 'active').

**Контраст с Примером 2**: reject self допустим — это отмена
request'а, не approval. Self-reject НЕ alerting-worthy.

---

## Пример 4 (edge): duplicate request на held user блокирован

### 4.1 Create pending на u-target (u-alice)
→ 201, h-123 pending.

### 4.2 u-alice или u-bob пытается создать второй pending на
u-target:

```
POST /api/legal-holds
{"target_user_id":"u-target","case_ref":"DOJ-999","reason":"other case"}
```

**Response 409:**
```json
{"error": "user already has blocking hold"}
```

**Side effects:**
- `admin_event_logs`: action=apply_hold_requested, success=false,
  metadata: `{error_code:"already_blocking", case_ref_hash:"<16hex>"}`.

**Контраст с PR-L2.2**: раньше blocking index покрывал только
active. Теперь покрывает pending+active → второй pending тоже
блокируется (иначе creator мог бы spam'ить requests в обход 4-eyes).

---

## Пример 5 (failure): approve на уже active → 409

### 5.1 Create + approve → status=active.
### 5.2 Третий admin u-carol пытается approve снова:

```
POST /api/legal-holds/h-123/approve     (token=u-carol)
```

**Response 409:**
```json
{"error": "hold is not pending"}
```

**Side effects:**
- `admin_event_logs`: success=false,
  `metadata.error_code="not_pending"`.
- Hold без изменений.

**Rationale**: approve — transition pending→active, не повторяемая
операция. Для дополнительного admin'ского ack — используйте
отдельный event-log entry вне state machine hold'а.

---

## Пример 6 (failure): release на pending → 409

Pending hold нельзя release'ить — для cancel используется reject.

```
POST /api/legal-holds/h-123/release     (h-123 is pending)
```

**Response 409** (через IsNotActive path — существующая
идемпотентность Release, но здесь hold НЕ был active и НЕ
released — сигнал operator'у использовать reject).

Actually: repo возвращает ErrNotActive; handler'у в этом случае
корректно переводит в 200 "already_released". **Это гейп — см.
notes ниже**.

### Notes на Пример 6

В реализации PR-L2.3 Release на pending даёт 200
"already_released" — т.к. pending ≠ active, Release
интерпретирует как "already released". Это разумно, но может
запутать operator'а. Docs явно направляют reject для pending.

---

## Пример 7 (regression guard): pending не защищает audit от purge

### Setup
- Create pending hold h-123 на u-target (status=pending).
- audit_logs имеет row старше retention cutoff для u-target.

### Действие
- Scheduler tick: `PurgeOlderThanRespectingHoldsAndRecordRun`.

### Ожидание
- Row для u-target **УДАЛЯЕТСЯ** (NOT EXISTS проверяет только
  `status='active'`).
- `audit_purge_runs` записывает rows_deleted >= 1.

### Контраст
- Если approve'ним h-123 до tick'а → row protected.
- Этот asymmetry — by design: pending — это request without
  compliance-эффекта.

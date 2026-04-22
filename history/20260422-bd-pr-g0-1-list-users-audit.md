# PR-G0.1: User-list access audit для GET /api/users

## Контекст
Расширение PR-G0 (user-read access audit) на list-scope. PR-G0
покрывал `GET /api/users/{id}` (targeted read одного пользователя);
`GET /api/users` (ListUsers) оставался `[gap]` в privacy-ops runbook
§8.5.

Маленький security follow-up после L-1 core/enterprise split.

## Цель
Закрыть «кто когда скачал весь список пользователей» — это другой
forensic-вопрос, чем «кто прочитал конкретного юзера». В регулируемой
enterprise-среде list-scan имеет отдельный signal: может быть
legitimate (admin UI dashboard), может быть подозрительным
(подготовка к exfiltration). Separate event позволяет SIEM-правилам
отличать.

## Scope (In)
- `authHandler.recordUsersList` helper (nil-safe).
- Integration в `ListUsers`:
  - success path (200) → event с `user_count` metadata;
  - failure path (500 repo error) → event с `success=false` +
    `error="repo_failure"` metadata.
- Privacy-контракт: metadata НЕ содержит emails/api_keys/role list —
  response body уже их имеет; дублировать PII в `admin_event_logs`
  избыточно и увеличивает surface.
- 4 TDD теста под `//go:build enterprise`.
- Runbook §8.5: ListUsers [gap] → [implemented] + changelog 1.2.

## Scope (Out / follow-up)
- **PR-G0.2**: UpdateUser audit (PUT /api/users/{id}). Сейчас
  остаётся [gap] в §8.5.
- SIEM integration для list-events — отдельный roadmap.

## Тесты (4 новых, все зелёные)
- `TestRecordUsersList_NilRecorder` — Core-build safety guard
  (nil adminAudit → no-op, не panic).
- `TestRecordUsersList_WritesEvent` — happy path; проверяет shape
  (action=list, resource=users, empty target_id, actor, metadata.
  user_count) + privacy guard (нет emails/api_keys в metadata).
- `TestRecordUsersList_FailureStatus` — failure path пишет event
  с success=false.
- `TestRecordUsersList_UnauthenticatedActor` — missing claims
  (middleware edge case) → actor_user_id=nil, event всё равно
  пишется.

## Definition of Done
- [x] `recordUsersList` helper + ListUsers integration (handler.go).
- [x] 4 теста под `//go:build enterprise`, все зелёные.
- [x] Regression: `go test ./...` и `go test -tags enterprise ./...`
      полностью зелёные.
- [x] Runbook §8.5 обновлён, changelog entry 1.2 добавлен.
- [x] History-файл (этот).

## Проверка
```bash
cd backend
go test -tags enterprise ./internal/auth -run TestRecordUsersList -v  # 4/4 PASS
go test ./... -count=1                                                  # все пакеты OK
go test -tags enterprise ./... -count=1                                 # все пакеты OK
```

Ручная проверка (после deploy с enterprise tag):
```bash
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/api/users | jq
# Затем проверить admin_event_logs:
psql "$DATABASE_URL" -c "SELECT actor_user_id, action, resource,
  status_code, success, metadata
  FROM admin_event_logs
  WHERE action='list' AND resource='users'
  ORDER BY created_at DESC LIMIT 1;"
```

## Риски / допущения
- Core build (`go build ./cmd/shadowai` без tag): `h.adminAudit=nil`,
  recordUsersList no-op, endpoint работает без admin_event_logs
  записи. Это acceptable — retention/audit features — enterprise
  scope по ENTERPRISE.md.
- Failure-path event: возможен «двойной write» при проблемах с PG —
  repo.ListUsers fail + recordUsersList тоже через adminAudit
  (тоже в PG). Если PG недоступна полностью, просто оба fail
  silently (adminaudit.Service имеет fail-open logger).

## History
- Plan: этот файл.
- Examples: `20260422-bd-pr-g0-1-examples.md`.

## Roadmap
- **PR-G0.2** — UpdateUser audit (следующий логический шаг).
- **SIEM integration** — mirror admin_event_logs в Splunk/Elastic/
  CloudTrail.

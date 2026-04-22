# PR-G0.2: UpdateUser access audit для PUT /api/users/{id}

## Контекст
Завершающий шаг admin user-governance trail. До PR-G0.2:
- PR-G0 (read) — GET /api/users/{id} пишется в admin_event_logs;
- PR-G0.1 (list) — GET /api/users пишется.
- PR-B — POST /users/{id}/erase пишется (через recordErase).
- **UpdateUser (PUT) — единственный оставшийся [gap]** в §8.5.

PR-G0.2 закрывает этот gap. После merge весь user-governance trail
(`read | list | update | erase`) покрыт.

## Цель
Forensic-вопросы, на которые теперь можно отвечать через
`admin_event_logs`:
1. Кто и когда поменял роль пользователя X? (action=update +
   metadata.changed_fields ⊇ ["role"] + old/new_role).
2. Какие пользователи были активированы/деактивированы админом Y
   за последний месяц? (action=update + metadata.old_is_active,
   new_is_active).
3. Кто пытался изменить роль, но получил 400 invalid_role?
   (success=false + metadata.attempted_role) — признак
   misconfigured UI или подозрительной активности.

## Scope (In)
- `authHandler.recordUserUpdate` helper (nil-safe, под `//go:build
  enterprise` поведенчески — integration hook в core handler).
- Integration в `UpdateUser`:
  - 200 success → event с diff-metadata (`changed_fields`,
    `old_role`/`new_role`, `old_is_active`/`new_is_active`,
    `email_changed` flag).
  - 404 user not found → event success=false.
  - 400 invalid_json → event success=false + `error`.
  - 400 invalid_role → event success=false + `attempted_role`
    (НЕ нормализованный — для отслеживания typo/attack).
  - 500 repo_failure → event success=false.
- 5 TDD тестов под `//go:build enterprise`.
- Runbook §8.5: UpdateUser `[gap]` → `[implemented]` + changelog
  1.3.

## Privacy-контракт
Metadata НЕ содержит:
- raw email (ни старый, ни новый) — только `email_changed: bool`
  и `old_email_empty: bool` (fix incomplete account vs reassign);
- passwords — UpdateUser их и не меняет (отдельный endpoint), но
  защита избыточна;
- api_key — никогда;
- хешей чего-либо.

Metadata содержит:
- `changed_fields`: `["role"]`, `["email", "is_active"]` и т.п.;
- `old_role`, `new_role` — нормализованные role-строки (не PII);
- `old_is_active`, `new_is_active` — bool (не PII).

TDD-тест `TestRecordUserUpdate_EmailChange_NoEmailInMetadata`
гарантирует, что handler не кладёт raw email в metadata (ищет
`@` в значениях).

## Scope (Out / follow-up)
- **SIEM integration** — mirror admin_event_logs в Splunk/Elastic/
  CloudTrail (следующий трек после G0.2).
- **4-eyes policy для UpdateUser** — любое изменение роли на
  `admin` требует второго approver. §8.6 роадмап.

## Тесты (5 новых)
1. `TestRecordUserUpdate_NilRecorder` — Core build safety
   (nil adminAudit → no-op).
2. `TestRecordUserUpdate_WritesEvent` — happy path; проверяет
   shape (action=update, resource=user, target_id, actor) +
   privacy guard (нет email/password/api_key в metadata).
3. `TestRecordUserUpdate_FailurePaths` — table-driven: 4 sub-cases
   (not_found, invalid_json, invalid_role, repo_failure), все
   пишут event с success=false.
4. `TestRecordUserUpdate_UnauthenticatedActor` — nil claims →
   actor_user_id=null, event всё равно пишется.
5. `TestRecordUserUpdate_EmailChange_NoEmailInMetadata` — regression
   guard: проверка что '@' не просачивается в metadata-строки.

## Definition of Done
- [x] recordUserUpdate helper + UpdateUser integration.
- [x] 5 TDD-тестов под `//go:build enterprise`, все зелёные.
- [x] Regression: `go build ./...`, `go build -tags enterprise ./...`,
      `go test ./... -count=1`, `go test -tags enterprise ./... -count=1`
      — всё чисто.
- [x] Runbook §8.5 обновлён, changelog 1.3 добавлен.
- [x] History + examples.

## Проверка
```bash
cd backend
go test -tags enterprise ./internal/auth -run TestRecordUserUpdate -v
# 5 тестов PASS
```

Ручная (после deploy с enterprise tag):
```bash
# Change role → expect admin_event с diff
curl -s -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}' \
  http://localhost:8080/api/users/u-target

psql "$DATABASE_URL" -c "
  SELECT actor_user_id, action, target_id, success,
         metadata->'changed_fields' AS changed,
         metadata->>'old_role' AS old, metadata->>'new_role' AS new
  FROM admin_event_logs
  WHERE action='update' AND resource='user'
  ORDER BY created_at DESC LIMIT 1;"
```

## Риски / допущения
- Diff metadata увеличивает size admin_event_logs per row (vs read/
  list events). При AdminAuditRetentionDays=365 и активном
  user-management это может быть десятки MB/год — acceptable.
- Attempted role normalization — в metadata пишем НЕ нормализованное
  значение (raw input от клиента). Это сознательно: SIEM должен
  увидеть точно что пришло, чтобы детектить typos vs injection.
- Email сравниваем `!= existing.Email`; если клиент прислал тот же
  email — `email_changed=false`, event не засоряется лишним
  флагом.

## History
- Plan: этот файл.
- Examples: `20260422-bd-pr-g0-2-examples.md`.

## Roadmap
- ✅ PR-G0 (read) / PR-G0.1 (list) / PR-G0.2 (update) / PR-B (erase) —
  полный admin user-governance trail.
- Next: **SIEM integration** → mirror admin_event_logs в external
  append-only storage.

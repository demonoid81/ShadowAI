# PR-G1: Provider/Model Governance (phase 1)

## Контекст
Первая phase Provider/Model Governance в enterprise-линии. Scope
зафиксирован пользователем:

**Входит в PR-G1:**
- allowlist провайдеров;
- allowlist моделей внутри провайдера;
- deny-by-default (через Mode=allowlist_strict);
- policy visibility / status (admin GET);
- audit/admin-event на policy deny.

**НЕ входит (G2/G3):**
- role-based routing;
- department/user policy matrix;
- sensitivity-aware routing;
- DPA/compliance inventory UI/reporting.

Этот PR — enterprise scope. Работа ведётся в branch
`pr-g1-provider-model-governance` на базе `enterprise-main` (=master
+ PR-A/B/D/D.1/E/G0 merged). НЕ merge в публичный Apache core.

## Цель
Enterprise-клиент (regulated: банки, страхование, госсектор) получает
централизованный контроль над тем, какие LLM-провайдеры и модели
разрешены. Deny-by-default снимает класс рисков «пользователь
отправил данные в несанкционированный endpoint».

## Scope (In)
- Domain: `governance.Mode` (disabled/allowlist_strict),
  `Policy`, `ProviderRule`, `Decision`.
- Service: `Evaluate(ctx, provider, model)`, `GetActive`, `Upsert`.
  Fail-closed при repo error (compliance control не должен быть
  fail-open).
- Repository: PG-backed singleton с `is_active` partial-unique index.
- HTTP handler: GET `/api/governance/policy`, PUT `/api/governance/
  policy` (admin-only).
- Wiring в proxy.ProxyChat (enforcement после model-validation,
  до firewall) и UnifiedChat (filter candidates после router.Route).
- admin_event_logs запись при deny: `action=policy_deny`,
  `resource=provider_model`, `target_id=<provider>/<model>`.

## Scope (Out, roadmap)
- **PR-G2**: Mode=role_based, per-role allowlist, matrix (user/
  department × provider/model), SSO-driven role source.
- **PR-G3**: compliance inventory UI (DPA, vendor-risk-tier, SLA
  matrix, expiry tracking).
- **G4**: egress-level enforcement (L7 proxy block как second line).
- **v2+**: policy history (supersede-chain), change approval
  workflow (4-eyes для policy changes), policy diff export.

## План реализации (факт)

1. `backend/internal/governance/policy.go` — domain types (Mode,
   Policy, ProviderRule, Decision, codes).
2. `backend/internal/governance/service.go` — Evaluate + GetActive +
   Upsert (validate Mode).
3. `backend/internal/governance/service_test.go` — 11 unit-тестов:
   nil service, no policy, disabled, allow-known-pair, deny-unknown-
   provider, deny-unknown-model, empty-rules deny-all, empty-models
   deny-all, case-insensitive, repo-error fail-closed, Mode.IsValid.
4. `backend/migrations/012_create_provider_governance_policies.sql`
   — таблица с JSONB rules + singleton-constraint + seed-row в
   disabled-mode.
5. `backend/internal/governance/repository.go` — PGRepository
   (GetActive, Upsert с SELECT→INSERT/UPDATE разветвлением).
6. `backend/internal/governance/handler.go` — HTTP CRUD + admin
   audit recording.
7. `backend/internal/governance/handler_test.go` — 7 handler-тестов:
   empty config, return active, admin-only, unauthenticated, invalid
   mode, happy path, bad JSON.
8. `backend/internal/proxy/handler.go` — поля `governanceSvc`,
   `adminAudit` в `Handler`, параметры в `NewHandler`, вставка
   Evaluate после model validation в ProxyChat, фильтр candidates
   в UnifiedChat, helper `recordGovernanceDeny`.
9. `backend/internal/proxy/handler_governance_wiring_test.go` —
   4 integration-теста: deny unknown provider, deny unknown model,
   allow passes through, Mode=disabled allows all, + nil-governance
   backward test.
10. `backend/cmd/shadowai/main.go` — wiring governance service,
    handler, admin-only routes.
11. История и документация.

## Definition of Done
- [x] Все тесты governance package зелёные (11 unit + 7 handler).
- [x] Все тесты proxy package зелёные (4 governance wiring + весь
      остальной regression — 0 failures).
- [x] `go build ./...` чистая.
- [x] Migration SQL готов к apply (миграция сама по себе не
      применяется автоматически — это делает migration runner при
      следующем старте binary).
- [x] Proxy integration подтверждена wiring-тестом (deny → 403 +
      admin_event).
- [x] History + examples.

## Проверка
```bash
cd backend
go test ./internal/governance -v -count=1      # 18/18 PASS
go test ./internal/proxy -run Governance -v     # 4/4 PASS
go test ./... -count=1                           # все пакеты OK
```

Проверка миграции:
```sql
-- После apply migration 012:
SELECT mode, rules_json, is_active FROM provider_governance_policies;
-- Ожидаем: 1 row, mode='disabled', rules_json='[]', is_active=true
```

Ручная проверка HTTP (после deploy):
```bash
# GET active
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/api/governance/policy
# => {"id":"...","mode":"disabled","rules":[],...}

# PUT: enable strict allowlist
curl -s -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"allowlist_strict","rules":[
        {"provider":"openai","models":["gpt-4o","gpt-4o-mini"]}
      ]}' \
  http://localhost:8080/api/governance/policy

# Проба denied (anthropic не в allowlist):
curl -s -X POST -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3-opus","messages":[{"role":"user","content":"hi"}]}' \
  http://localhost:8080/proxy/anthropic/v1/messages
# => 403 {"code":"unknown_provider","reason":"провайдер \"anthropic\" не в governance-allowlist",...}
```

## Риски / зависимости
- **Зависимость**: миграция 010 (admin_event_logs) должна быть
  применена до 012 — PR-D уже содержит 010, 012 корректно
  использует `adminaudit.Recorder`.
- **Риск**: fail-closed при repo error может сломать весь proxy
  во время инцидента с PG. Смягчается тем, что audit/policy/budget
  тоже читают из PG — если PG down, proxy уже деградирован.
- **Риск**: case-insensitive матч — если оператор случайно добавит
  "OpenAI" и "openai" как две записи, будет дубликат. Смягчается
  тем, что в phase 1 применяется только первое найденное правило
  (loop exits on first provider match).
- **Известное ограничение v1**: нет UI для редактирования политики —
  только curl/REST. UI добавится в отдельном маленьком
  follow-up PR (frontend-only).

## Допущения
- Репозиторий `enterprise-main` ещё не существует (shadowai-enterprise
  repo не создан). Работа ведётся в локальной ветке; после создания
  оператором — cherry-pick этого PR-G1 стека в enterprise repo.
- Migration runner подхватывает файлы в `backend/migrations/` по
  порядку номеров (текущая механика). Если нужна отдельная
  миграция-группа для enterprise — это обсуждение PR-G2.

## History
- Plan: этот файл (`20260422-bd-pr-g1-provider-governance.md`).
- Examples: `20260422-bd-pr-g1-examples.md`.

## Roadmap
- **v1 (этот PR)**: allowlist + deny-by-default + visibility +
  audit deny.
- **v1.1 (follow-up)**: Frontend UI для CRUD policy (Vue компонент
  в admin dashboard).
- **v2 (PR-G2)**: Mode=role_based, role matrix, SSO-driven role
  source.
- **v3 (PR-G3)**: compliance inventory UI.
- **v4+**: policy history/diff, approval workflow, L7 egress.

## Review-fix #1 (2026-04-22)

### Medium: Policy rules — order-dependent Evaluate + no dedup
Ревьюер заметил, что Evaluate останавливался на первом matching
provider rule и возвращал `unknown_model`, если этот rule не
содержит запрошенную модель — даже если вторая matching rule
(например case-duplicate `openai` vs `OpenAI`) разрешает её.
Handler и Repository сохраняли Rules без дедупликации/нормализации.

**Fix (defence-in-depth):**

1. `service.normalizeRules` — lowercase provider/model, merge
   duplicate providers (union моделей), dedupe моделей within rule,
   стабильный порядок. Вызывается в `Service.Upsert` перед
   `repo.Upsert`. В БД всегда canonical form.
2. `service.Evaluate` — обходит ВСЕ matching provider rules вместо
   остановки на первом. Флаг `matchedProvider` различает
   `unknown_model` vs `unknown_provider` в финальном Deny. Даже если
   direct-SQL вставит non-canonical rules, Evaluate работает
   корректно.

**Тесты (7 новых, все red → green):**
- `TestEvaluate_DuplicateProviderCaseVariants_MergesMatches`
- `TestEvaluate_DuplicateProviderExact_MergesMatches`
- `TestEvaluate_DuplicateProvider_ModelInNeitherRule`
- `TestUpsert_NormalizesProviderCasing`
- `TestUpsert_MergesDuplicateProviders`
- `TestUpsert_DedupesModelsWithinRule`
- `TestUpsert_SkipsEmptyProviderName`
- `TestUpsert_StableOrdering`

### Low: Misleading comment в main.go wiring
Старый комментарий утверждал, что при отсутствии таблицы
`GetActive` возвращает `(nil, nil) → governance_disabled`.
Фактически repository.go возвращает `(nil, nil)` только для
`sql.ErrNoRows`; missing table — это другая ошибка, которая
попадает в fail-closed path (Deny всех запросов).

**Fix:** обновлён комментарий в `main.go`: migration 012
обозначен как ОБЯЗАТЕЛЬНЫЙ, soft-disable производится через
admin API с Mode=disabled, не через пропуск миграции.
Empty state (migration есть, записей нет) обрабатывается
корректно за счёт seed-row в migration.

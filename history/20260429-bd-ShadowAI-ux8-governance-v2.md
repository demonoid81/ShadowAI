# bd ShadowAI-ux8 — Governance Policy v2 UI

## Контекст

Backend содержит enterprise governance endpoint `GET/PUT /api/governance/policy` с режимами `disabled`, `allowlist_strict`, `role_based`, `context_scoped`. Frontend до задачи показывал только legacy `/api/policies`, поэтому provider/model routing, department/sensitivity и role-based controls оставались API-only workflow.

CASS проверен через project-scoped запрос:

```bash
cass search "UX8 governance policy v2 frontend context scoped" --workspace /home/developer/Projects/ShadowAI --toon --limit 5
```

Отдельных UX8-решений в CASS не найдено. Контракт восстановлен из фактического кода `backend/internal/governance/handler.go`, `types.go`, `service.go` и текущего `PoliciesPage.vue`.

## Цель

Добавить Governance Policy v2 UI на странице Policies:

- читать active governance policy;
- редактировать mode;
- строить provider/model allowlist;
- строить role-based rules;
- строить context_scoped rules по department, role, sensitivity;
- показывать backend validation errors;
- оставить legacy policy_rules как отдельный migration split.

## План реализации

1. Поднять backend contract через ast-index и точечное чтение файлов.
2. Добавить utility-функции и TDD-тесты для provider/model normalization и risk warnings.
3. Добавить typed API client `src/api/governance.ts`.
4. Добавить composable `useGovernancePolicy`.
5. Добавить компоненты `ProviderRulesEditor`, `RoleRulesEditor`, `ContextRulesEditor`, `GovernancePolicyPanel`.
6. Переписать `PoliciesPage.vue` под Governance v2 + legacy split.
7. Добавить ru/en i18n и выполнить build/tests.

## Размышления

Рассмотрены варианты заменить legacy `/api/policies` полностью или сохранить на той же странице. Принято решение сохранить legacy block ниже Governance v2, потому что bd scope явно не требует удаления старой страницы, а резкое удаление могло бы сломать существующий firewall rules workflow.

Рассмотрены варианты сделать только JSON editor или structured editor. JSON-only отклонён: он не выполняет UX8 DoD для context_scoped без raw JSON-only workflow. Принято решение сделать structured editors и оставить JSON fallback как safety valve.

Рассмотрены варианты блокировать save на frontend warnings или разрешать save и полагаться на backend. Принято решение показывать warnings, но final validation оставлять backend-у: это соответствует контракту `ValidationError → 400`, снижает риск расхождения UI/backend rules и не создаёт ложную уверенность.

Рассмотрены варианты расширять backend simulation/dry-run endpoint. Отклонено как out of scope, потому что backend endpoint для simulation отсутствует; UI не должен имитировать enforcement.

## Реализация

- `frontend/src/api/governance.ts` — typed client для `GET/PUT /governance/policy`.
- `frontend/src/composables/useGovernancePolicy.ts` — load/save/apply JSON fallback, backend error handling.
- `frontend/src/utils/governanceUi.ts` — normalization, empty drafts, warnings, stable JSON.
- `frontend/src/components/governance/*` — structured editors.
- `frontend/src/pages/PoliciesPage.vue` — Governance v2 screen + legacy split.
- `frontend/src/locales/{ru,en}.json` — локализация.
- `frontend/tests/governanceUi.test.ts` — utility coverage.

## Roadmap

### v1

- Structured Governance Policy v2 editor.
- ContextRule editor для department/role/sensitivity.
- Provider/model builder.
- Role-based builder.
- JSON fallback + normalized preview.
- Legacy policy_rules сохранён как migration split.

### v2+

- Policy simulation/dry-run после появления backend endpoint.
- Policy diff approval / four-eyes для governance changes.
- Server-side import/export policy JSON.
- Route-level separation legacy policies vs governance v2, если legacy rules будут официально deprecated.

## Проверка

- `npm run test:governance-ui`.
- `npm run build`.
- `go test -tags enterprise ./internal/governance ./cmd/shadowai`.
- `go test -tags enterprise ./...`.
- `git diff --check`.
- `ast-index update`.

# PR-G2: Role-based governance (phase 2)

## Контекст
PR-G1 дал strict allowlist — все роли получают одинаковый список
разрешённых (provider, model) пар. Regulated enterprise сразу
задаёт вопрос: «можно ли analyst'у только cheap/fast models, а
admin'у — весь каталог?». PR-G2 закрывает это через
`Mode=role_based`.

## Цель
Per-role allowlist: каждая роль получает свой список (provider,
model) пар. Deny-by-default для не-перечисленных ролей.

## Scope (In)

### 1. Core types (Apache, types.go)
- `ModeAllowlistRoleBased = "role_based"`.
- `CodeUnknownRole = "unknown_role"`.
- `RoleRule{Role, Rules}` struct.
- `Policy.RoleRules []RoleRule`.
- **Breaking change**: `Evaluator.Evaluate(ctx, role, provider, model)`
  — добавлен `role` параметр. Role применяется только при
  Mode=role_based; в strict/disabled ignored. Proxy всегда передаёт
  `claims.Role`.

### 2. Service (enterprise, service.go)
- `evaluateRules` — общая функция для strict и role-scoped
  evaluation.
- `evaluateRoleRules` — находит matching RoleRule по role
  (case-insensitive), применяет `evaluateRules` к его rules.
  Unknown role → Deny/CodeUnknownRole.
- `normalizeRoleRules` — lowercase роли, merge duplicate-role
  entries (union rules), внутри каждого role применяет
  `normalizeRules`, stable sort.
- `Service.Upsert` нормализует и Rules, и RoleRules.

### 3. Repository (enterprise, repository.go)
- Migration 014 добавляет `role_rules_json JSONB DEFAULT '[]'`.
- GetActive читает role_rules_json, Unmarshal в `Policy.RoleRules`.
- Upsert сохраняет role_rules_json (INSERT и UPDATE).

### 4. Handler (enterprise, handler.go)
- `upsertRequest.RoleRules []RoleRule`.
- `policyResponse.RoleRules` включается в GET.
- `recordAdmin` metadata получает `role_rule_count`.

### 5. Proxy integration (core file, Apache hook)
- `ProxyChat`: `h.governanceSvc.Evaluate(r.Context(), claims.Role,
  providerName, model)`.
- `UnifiedChat`: аналогично в candidate filter loop.
- Nil-safe: `h.governanceSvc == nil` — короткозамыкает (Core build).

## Scope (Out, PR-G3+)
- Multi-policy с scope (department/team/tenant).
- Sensitivity-aware routing (tag-based: PII → restricted models).
- Compliance inventory UI (DPA, vendor risk tier, SLA matrix).
- Wildcard matching (`*` для "all models of provider").
- Role hierarchies (admin inherits analyst's access).

## Tests

### governance/service_test.go (8 новых)
- `TestEvaluate_RoleBased_AllowsKnownTriple` — happy path.
- `TestEvaluate_RoleBased_DeniesPrivilegedModelForLesserRole` —
  analyst → admin-only model → Deny/unknown_model.
- `TestEvaluate_RoleBased_UnknownRole_Denied` — role не в RoleRules
  → Deny/unknown_role.
- `TestEvaluate_RoleBased_EmptyRoleRules_DeniesAll` — misconfigured
  policy.
- `TestEvaluate_RoleBased_UnknownProvider` — role matched, provider
  outside role scope.
- `TestEvaluate_RoleBased_CaseInsensitive` — Admin/admin,
  OpenAI/openai все match.
- `TestEvaluate_StrictMode_IgnoresRole` — backward compat.
- `TestUpsert_RoleBased_NormalizesRoleNames` — dup roles merge +
  sort.
- `TestUpsert_RoleBased_SkipsEmptyRoleName` — empty role отсекается.

Обновлён `TestMode_IsValid`: role_based=true, device_scope=false.
Все существующие `Evaluate(ctx, provider, model)` обновлены на
`Evaluate(ctx, "", provider, model)` (role=empty для
strict/disabled).

### proxy/handler_governance_wiring_test.go (2 новых)
- `TestProxyChat_RoleBased_AdminAllowedAnalystDenied` — claims.Role
  правильно пробрасывается; модель разрешена admin'у, не analyst'у.
- `TestProxyChat_RoleBased_UnknownRoleDenied` — unknown role → 403
  + code=unknown_role + admin event.

### governance/handler_test.go (обновлён 1)
- `TestUpdatePolicy_InvalidMode_Rejected` — role_based теперь
  валиден; переключён на `device_scope` как unknown.

## Acceptance
- [x] Admin-allowed / analyst-denied на одну и ту же модель.
- [x] Mode=allowlist_strict продолжает работать (PR-G1 backward
      compat).
- [x] Mode=disabled ничего не блокирует.
- [x] Unknown role → Deny/unknown_role (deny-by-default).
- [x] go build ./... + go build -tags enterprise ./... — оба green.
- [x] Core + enterprise matrix tests полностью зелёные.
- [x] Migration 014 idempotent (IF NOT EXISTS).

## Проверка
```bash
cd backend
go test -tags enterprise ./internal/governance -run RoleBased -v
go test -tags enterprise ./internal/proxy -run RoleBased -v
go test ./... -count=1
go test -tags enterprise ./... -count=1
```

Ручная (после deploy enterprise + migrations 012+014):
```bash
# Upsert role-based policy:
curl -X PUT -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{
    "mode":"role_based","rules":[],
    "role_rules":[
      {"role":"admin","rules":[{"provider":"openai","models":["gpt-4o","gpt-4o-mini","o1-preview"]}]},
      {"role":"analyst","rules":[{"provider":"openai","models":["gpt-4o-mini"]}]}
    ]
  }' \
  http://localhost:8080/api/governance/policy

# Analyst → expensive model → 403:
curl -X POST -H "Authorization: Bearer $ANALYST" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}' \
  http://localhost:8080/proxy/openai/v1/chat/completions
# → 403 { "code":"unknown_model", ... }

# Admin → тот же запрос → forwarded.
```

## Риски / допущения
- **Breaking signature change**: `Evaluator.Evaluate` теперь
  принимает role. Все внутренние callsites обновлены; внешние
  consumers (если появятся) должны обновиться.
- **Unknown role — deny**: новая роль в системе (через SSO claim)
  без явного добавления в RoleRules → блок для всех users этой
  роли. SIEM metric `shadowai_siem_fail_total` + admin events с
  code=unknown_role дают operator'у forensic signal.
- **Role caching**: Evaluate читает policy каждый раз из БД.
  Per-request overhead = 1 SELECT. Для high-traffic deploy'ов
  imperative caching with TTL — v2.1 roadmap, не G2.

## History
- Plan: этот файл.
- Related: PR-G1 (phase 1 strict allowlist).

## Roadmap
1. Legal hold v2 — retention-aware purge, 4-eyes approver, scope.
2. WORM primary storage.
3. SIEM v1.1 (syslog/OTel/batching).
4. G2.1 — policy caching для high-traffic.
5. G3 — department scope, sensitivity-aware routing.
6. Firewall/runtime track — semantic_v2 rollout, PR-7 streaming.

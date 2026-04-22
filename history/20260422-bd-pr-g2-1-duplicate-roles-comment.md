# PR-G2.1: Defence-in-depth для duplicate role entries + stale comment

## Контекст
Review PR-G2 — два finding'а.

1. **Medium** — `evaluateRoleRules` early-return на первом matching
   role entry. Если в БД оказались duplicate entries (admin +
   Admin через direct SQL / legacy import / corruption),
   split-модели могли incorrectly deny'иться. Write-path
   (normalizeRoleRules) уже защищён, но read-path — нет. Та же
   категория бага, что я фиксил в PR-G1 review для duplicate
   **providers** — тогда я применил defence-in-depth (normalize
   on write + evaluateRules обходит всех matching). В G2 только
   write-side был защищён. G2.1 закрывает read-side тоже.

2. **Low** — package comment в `types.go:16` всё ещё говорит
   "role-based governance не входит в v1", хотя в PR-G2 оно
   реализовано. Введение в заблуждение operator'а / developer'а.

## Scope (In)

### Fix #1: evaluateRoleRules — collect all matching
- Было: `for ... if EqualFold ... return evaluateRules(rr.Rules, ...)`.
  Early-return на первом match — split между entries терялся.
- Стало: `for ... if EqualFold ... matched = append(matched, rr.Rules...)`.
  Собираем rules со всех matching entries, затем применяем
  `evaluateRules` (который уже PR-G1-robust к duplicate
  providers после review fix `a43f299`).
- `nil`-check на `matched`: роль не встретилась ни в одной
  записи → Deny/unknown_role (prev behavior сохранён).

### Fix #2: stale package comment
- Было: `// НЕ входит в v1: - role-based routing (PR-G2); ...`
- Стало:
  ```
  // Входит в phase 2 (PR-G2):
  //   - role_based Mode — per-role allowlist ...
  // НЕ входит в phase 2 (roadmap):
  //   - department/user policy matrix (PR-G3);
  //   - sensitivity-aware routing (PR-G3);
  //   - DPA/compliance inventory UI/reporting (PR-G3);
  //   - policy caching для high-traffic deploys (PR-G2.1).
  ```

## Regression test (1 новый)

`TestEvaluate_RoleBased_DuplicateRoleEntries_MergesMatches`:
- Policy имеет two entries: `Admin[gpt-4]` + `admin[gpt-4o-mini]`.
- Pre-fix: запрос `admin/openai/gpt-4o-mini` → early-return на
  "Admin", модель не найдена → Deny/unknown_model.
- Post-fix: обе модели из обоих entries доступны для role="admin";
  gpt-4, gpt-4o-mini — Allow; gpt-5-beta (ни в одной) —
  Deny/unknown_model.

## Acceptance
- [x] Duplicate role entries с split model sets больше не ломают
      Evaluate.
- [x] Stale comment обновлён.
- [x] `go build ./...` + `-tags enterprise` — оба green.
- [x] `go test ./... -count=1` + `-tags enterprise ./... -count=1` —
      полный matrix green.

## Проверка
```bash
cd backend
go test -tags enterprise ./internal/governance -run Duplicate -v
go test ./... -count=1
go test -tags enterprise ./... -count=1
```

## Риски / допущения
- **Оптимизация**: для policy с большим числом duplicate role
  entries overhead O(N) против O(1) early-return. В реальности
  N-маленькое (policy singleton, admin не создаёт десятки
  duplicate через UI — только через corruption). Acceptable.
- **normalize on read** не добавлял: избыточно при active
  normalize on write + robust evaluate. Если operator
  обеспокоен, отдельная defence — post-GetActive normalization —
  opcional v2.1 task.

## History
- Plan: этот файл.
- Related: PR-G2 (role-based groundwork), PR-G1 review fix
  `a43f299` (аналогичная проблема для providers).

## Roadmap (без изменений)
1. Legal hold v2.
2. WORM primary.
3. SIEM v1.1.
4. G2.2 — policy caching.
5. G3 — department scope, sensitivity routing.
6. Firewall/runtime.

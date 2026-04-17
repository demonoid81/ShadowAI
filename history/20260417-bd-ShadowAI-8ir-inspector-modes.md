# bd-ShadowAI-8ir: Inspector modes (disabled / shadow / enforce)

**Дата:** 2026-04-17
**Статус:** реализовано (PR-4 из backlog после Stage 1).

## Контекст

После PR-3 (wire Meta["flagged"] для MultiTurn) firewall pipeline готов,
но все инспекторы работают в единственном режиме — enforce. Это
создаёт операционный тупик:

- нельзя safely выкатить новый инспектор в prod — только "всё или
  ничего";
- отладить FP/FN нового инспектора на production traffic без риска
  заблокировать валидные запросы невозможно;
- отключить неустойчивый инспектор можно только redeploy'ем без
  него (кодовая правка + CI прогон).

PR-4 вводит три режима исполнения: `disabled`, `shadow`, `enforce`.

## Контракт режимов

- `disabled` — инспектор не запускается. Идентично "не зарегистрирован":
  ни аудита, ни метрик.
- `shadow` — инспектор исполняется, но pipeline НЕ применяет его
  решение. Shadow-наблюдение (inspector+action+reason+severity) попадает
  в `Decision.ShadowDecisions` и затем — в
  `audit_logs.shadow_decisions_json`. Метрика
  `shadowai_firewall_decisions_total` инкрементится с label `mode=shadow`.
  `payload.Meta["flagged"]` НЕ мутируется. `recordFlag()` НЕ вызывается.
  `SanitizedText` НЕ применяется. `finalAction/finalReason` не меняются.
  Для downstream семантически = allow.
- `enforce` — текущее поведение (до PR-4): Block/Sanitize/Flag
  применяются, cross-inspector signal через `Meta["flagged"]` работает.

## Resolution model

Единая функция `InspectorModes.For(name string) InspectorMode`:
```
Overrides[name] → Default → ModeEnforce
```

Nil-receiver безопасен: возвращает `ModeEnforce` (fail-safe default для
call-site'ов, которые ещё не в курсе PR-4).

### Источник конфигурации (MVP — env, не YAML)

```
FIREWALL_MODE_DEFAULT=enforce|shadow|disabled   # global default
FIREWALL_MODE_<INSPECTOR>=...                   # per-inspector override
```

Примеры:

```
FIREWALL_MODE_DEFAULT=enforce
FIREWALL_MODE_PII=shadow
FIREWALL_MODE_PROMPT_INJECTION=disabled
```

Имя в env → `UPPER_SNAKE_CASE`; в internal map лежит `lower_snake_case`,
чтобы совпадать с `Inspector.Name()`. Невалидные значения тихо
игнорируются (misconfig не валит приложение, оператор видит реальные
режимы через `/proxy/firewall/status`).

### Почему env, а не YAML

Проект уже полностью env-based (`backend/internal/config/config.go`).
Вводить YAML для одной фичи — scope creep. Internal struct
(`InspectorModes{Default, Overrides}`) отделён от loader'а, так что
будущий tenant-override layer плагинизируется поверх без перелопачивания
runtime.

## Реализация

### Pipeline refactor (`backend/internal/firewall/firewall.go`)

- `type pipelineEntry struct { inspector Inspector; mode InspectorMode }`
  (private — не light через Status(), которое делает type-switch на
  concrete Inspector).
- `NewPipeline()` — backward compat: `modes=nil`, все entries → enforce.
- `NewPipelineWithModes(*InspectorModes)` — production конструктор.
- `Register(i Inspector)` — резолвит mode один раз при регистрации
  через `p.modes.For(i.Name())`.
- `run()` — три ветки: disabled=skip, shadow=run+metric+append+continue,
  enforce=оригинал. Shadow Allow не пишется в ShadowDecisions
  (шум: каждый "чистый" запрос давал бы нулевую запись).

### Decision.ShadowDecisions

```go
type ShadowDecision struct {
    Inspector string   `json:"inspector"`
    Action    Action   `json:"action"`
    Reason    string   `json:"reason,omitempty"`
    Severity  Severity `json:"severity,omitempty"`
}
```

Findings-payload намеренно НЕ включён: не раздувает audit row, детали
остаются в логах инспектора.

### Метрики (`backend/internal/metrics/metrics.go`)

Добавлен label `mode` в `shadowai_firewall_decisions_total`. Cardinality:
≤ 2 phase × ≤ 10 inspector × 4 action × 2 mode = 160 (shadow+enforce;
disabled не пишет).

**Breaking note:** существующие dashboards, фильтрующие по трём labels,
теперь должны либо игнорировать `mode`, либо явно селектить
`mode="enforce"` для исторической семантики. Prometheus продолжит
записывать данные — алерты не ломаются, только разрезы.

### Audit storage

- Миграция `007_add_shadow_decisions_to_audit_logs.sql`:
  ```
  ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS shadow_decisions_json JSONB NULL;
  ```
- `domain.AuditLog.ShadowDecisionsJSON string`.
- `audit.Repository.Insert` / `.List` — читают/пишут новую колонку,
  пустая строка → `NULL` в Postgres (чтобы дашборды `WHERE ... IS NOT NULL`
  давали правильный счётчик).

### Handler wiring

Request-scoped shadow slot через context.Value:

- `withShadowSlot(ctx)` — создаёт slot в начале `ProxyChat` / `UnifiedChat`.
- `appendShadowDecisions(ctx, decs)` — после каждого успешного
  `firewall.Inspect*` call (6 мест: 3 в ProxyChat, 3 в UnifiedChat;
  на request-phase и двух response-phase ветках).
- `h.auditLog(ctx, log)` — тонкая обёртка над `auditSvc.Log`,
  которая стягивает shadow-decisions из context и сериализует в JSON.
  Применена через массовую замену `h.auditSvc.Log` → `h.auditLog(r.Context(), ...)`
  в 28 местах записи audit_logs.

**Почему context, а не явный прокид:**
прямой аргумент `aggregatedShadow` потребовал бы 28 отдельных правок
сигнатур + переменную-накопитель в каждой handler-функции. Context-value
hand-off держит всё в одном файле `audit_shadow.go` и не увеличивает
arity helper'ов.

**Важно:** `audit_logs.policy_action` **НЕ перегружен** shadow-
значениями. Там остаётся фактический enforcement-итог запроса
(`allowed/blocked/sanitized/warned`). Shadow-наблюдения живут в
отдельной колонке, поэтому ops-dashboards видят реальный outcome
независимо от того, сколько shadow-инспекторов сработало.

## Размышления

- Рассмотрены варианты:
  - (A) Public wrapper `modeAwareInspector{inner, mode}` вокруг каждого
    инспектора при Register. Отклонён: `Status()` использует type-switch
    на concrete type (`*PIIInspector`, `*JudgeBackedInspector` и т.д.);
    wrapper сломал бы все `case`-ветки, требуя unwrap'а.
  - (B) Внедрить `AuditWriter` в `Pipeline`, чтобы shadow писались
    прямо из pipeline. Отклонён: pipeline не знает endpoint, bodies,
    duration, tokens — это контекст handler'а. Протаскивание всего
    этого в Payload раздуло бы интерфейс или привело бы к дублирующим
    audit rows.
  - (C) Перегрузить `policy_action` значениями `shadow_blocked`.
    Отклонён: затер бы фактический outcome запроса; ломает смысл
    колонки ("что произошло с запросом" vs. "что один из shadow-
    инспекторов хотел сделать").
- Принято решение: `pipelineEntry` внутри pipeline (вариант B без DI),
  handler сам пишет audit с shadow через context-helper. Отдельная
  колонка `shadow_decisions_json JSONB NULL`.
- Альтернатива (YAML config для режимов) отклонена: текущая модель
  полностью env-based, YAML был бы scope creep.

## Definition of Done — выполнено

- [x] 10 тестов для `mode.go` (parser, resolver, env loader).
- [x] 8 тестов для `Pipeline` в новых режимах
      (`pipeline_modes_test.go`): shadow не блокирует, не мутирует
      Meta, не применяет SanitizedText, не вызывает RecordFlag, Allow
      не попадает в ShadowDecisions; disabled не исполняется; mixed
      mode с enforce-блокировкой; backward compat `NewPipeline()`.
- [x] 2 e2e-теста на handler wiring
      (`handler_shadow_wiring_test.go`): shadow inspector не блокирует
      request + пишет ShadowDecisionsJSON; enforce-only flow даёт
      пустой ShadowDecisionsJSON.
- [x] Metrics test проверяет label `mode="shadow"` и `mode="enforce"`.
- [x] Migration `007_add_shadow_decisions_to_audit_logs.sql` создана.
- [x] Repository Insert/List поддерживают новую колонку.
- [x] main.go wire: `NewPipelineWithModes(LoadInspectorModesFromEnv())`.
- [x] Все тесты backend зелёные (`go test ./...`).

## Roadmap

### v2+ (out of scope для PR-4, отдельные задачи)

- **Tenant-override layer.** Сейчас `InspectorModes.For(name)`
  глобальный. Будущий `For(tenantID, name)` накладывает
  `tenants[tenantID].Inspectors` поверх `Default`. Shape API готов
  принять этот layer без ломки call-site'ов.
- **Hot-reload режимов.** Сейчас mode резолвится при Register и далее
  неизменяем. Переконфигурация требует redeploy. HTTP endpoint
  `PATCH /proxy/firewall/modes` + atomic swap в `pipelineEntry.mode`
  даст zero-downtime изменения.
- **Shadow analytics view.** Вьюха поверх audit_logs, разворачивающая
  `shadow_decisions_json` в строки: `inspector, action, count, last_seen`.
  Попадает в ops-dashboard после того, как накопится несколько дней
  данных.
- **PR-5 FP/FN benchmark harness** использует shadow-режим как
  default для новых инспекторов: "новый инспектор всегда заходит в prod
  через shadow и повышается до enforce по precision/recall порогу".

## Проверка

```bash
cd backend
go test ./... -count=1   # full regression
go test ./internal/firewall -count=1 -v  # новые тесты режимов
go test ./internal/proxy -run ShadowInspector -count=1 -v  # e2e
```

Ожидаемо: все зелёные.

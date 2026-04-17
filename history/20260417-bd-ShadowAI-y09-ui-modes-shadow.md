# bd-ShadowAI-y09: PR-4.1 UI для inspector modes и shadow decisions

**Дата:** 2026-04-17
**Статус:** реализовано.

## Контекст

После PR-4 (`bd-ShadowAI-8ir`) в backend появились:
- runtime `InspectorMode` (enforce/shadow/disabled) с env-конфигом,
- `audit_logs.shadow_decisions_json` с JSONB наблюдениями shadow-
  инспекторов,
- метрика `shadowai_firewall_decisions_total` с label `mode`.

Проблема: admin UI не отражал новую семантику:
- `FirewallPage.vue` рисовал только `Enabled/Disabled`; инспектор с
  `mode=shadow` выглядел как обычный зелёный "Enabled" — оператор
  не видел факта, что инспектор работает без enforcement.
- `AuditLogPage.vue` фильтровал только `policy_action`; увидеть
  "запросы с shadow-наблюдениями" можно было только через SQL
  (`WHERE shadow_decisions_json IS NOT NULL`).
- `RequestTable.vue` не показывал shadow-сигнал вовсе.

PR-4.1 доводит PR-4 до operable state: новые возможности виден сразу
из админки.

## Реализация

### Backend

- `audit.Repo.List` получил 7-й параметр `hasShadow string`
  (значения `""|"any"|"yes"|"no"`):
  - `"yes"` → `AND shadow_decisions_json IS NOT NULL`
  - `"no"` → `AND shadow_decisions_json IS NULL`
  - `""`, `"any"` и любое мусорное значение → no-op
- `Handler.List` принимает `?has_shadow=...` и whitelist'ом нормализует:
  всё, что не `"yes"/"no"`, → `""` (fail-safe для старых клиентов
  и опечаток в UI).
- `captureAuditRepo` в тестах proxy обновлён под новую сигнатуру.
- Новый `internal/audit/handler_test.go` с 7-кейсовым whitelist-тестом
  и end-to-end проверкой, что `shadow_decisions_json` не теряется при
  сериализации response.

### Frontend

**FirewallPage.vue**
- `InspectorInfo.mode?: string` в TypeScript-типе.
- Два helper'а:
  - `modeClass(mode)` — цвета: enforce → нейтральный серый,
    shadow → жёлтый, disabled → приглушённый серый.
  - `modeLabel(mode)` — i18n-ключи `firewall.modeEnforce|Shadow|Disabled`.
- Mode badge рендерится **всегда** (в т.ч. для enforce) рядом с
  phase и enabled pill. Причина: после PR-4 сам факт режима стал
  частью runtime state; скрытие enforce возвращало бы оператора
  в "старый UI без режимов".

**AuditLogPage.vue**
- Dropdown `has_shadow` с тремя опциями (`shadowAny | shadowYes |
  shadowNo`) рядом с `policy_action`.
- `filters.has_shadow` прокидывается в `store.fetchLogs()`.
- Load-функция отсекает пустые параметры в query-string, чтобы сервер
  видел "отсутствие фильтра", а не пустую строку как фильтр.

**RequestTable.vue**
- Новая колонка `Shadow`.
- Рендер делегирован компоненту `ShadowCell.vue`.
- Клик по badge открывает `ShadowDecisionsModal.vue` с pretty-
  printed JSON.

**ShadowCell.vue** (новый)
- Парсит `log.shadow_decisions_json` (строка) изолированно от
  остальной строки таблицы.
- Три состояния:
  - `null/""` → `—` (placeholder, не кликабельный).
  - Parse failure / не-массив → `invalid shadow payload`,
    красный badge, открывает модалку с raw-текстом.
  - Валидный массив → жёлтый badge `shadow (N)`.

**ShadowDecisionsModal.vue** (новый)
- Teleport в `<body>`, backdrop-click закрытие.
- Три view'а: `invalid → показ raw`, `empty → hint`,
  `valid → JSON.stringify(_, null, 2)`.

### i18n

Новые ключи в `en.json` и `ru.json`:

```
firewall.mode, .modeEnforce, .modeShadow, .modeDisabled
audit.shadow, .shadowAny, .shadowYes, .shadowNo, .shadowCount,
      .shadowInvalid, .shadowModalTitle, .shadowModalEmpty
common.details
```

Названия режимов в RU оставлены en-технически (`enforce|shadow|disabled`) —
это принятая отраслевая терминология; перевод внёс бы
семантический drift (напр., "принудительный" ≠ enforce).

## Размышления

- Рассмотрены альтернативы RequestTable:
  - (A) Expandable row под кликнутой строкой. Отклонено:
    скачет высота таблицы, сложнее управлять состоянием при
    одновременном раскрытии нескольких строк.
  - (B) Tooltip с raw-JSON. Отклонено: плохой UX на длинных
    массивах + не позволяет копировать/скроллить.
  - (C) Модалка (выбрано): таблица плотная, JSON pretty-printed,
    поддерживает копирование.
- Рассмотрено выставление mode editable из UI. Отклонено: режимы
  резолвятся на Register (см. `firewall.Pipeline.Register`) и
  неизменяемы до redeploy. Hot-reload — v2 roadmap PR-4.
- Рассмотрено включение enforce badge только для ≠ enforce.
  Отклонено (по запросу): чтобы не вернуть operator'а в "старый UI"
  без визуального напоминания о режиме.

## Definition of Done

- [x] backend test `TestAuditHandler_HasShadow_Whitelist` — 7 кейсов.
- [x] backend test `TestAuditHandler_HasShadow_ReachesRepo_EndToEnd`.
- [x] `captureAuditRepo` обновлён, существующие 7 тестов в proxy
      не сломались.
- [x] Frontend `vue-tsc --noEmit && vite build` — зелёный.
- [x] `go test ./...` — зелёный.

## Что НЕ входит в этот PR (будет позже)

- Analytics view: топ-N инспекторов по shadow-частоте, timeline.
  Добавится, когда накопится 1–2 недели реальных данных.
- Editable modes из UI (требует hot-reload в backend — v2+).
- Клиентский shadow-counter rollup на уровне FirewallPage (сейчас
  оператор видит режимы + audit, аналитика по корреляции = SQL).

## Roadmap (v2+)

- Hot-reload: `PATCH /proxy/firewall/modes` + atomic swap в
  `pipelineEntry.mode`.
- Tenant-override layer (`FIREWALL_MODE_<TENANT>_<NAME>` или
  отдельная таблица `firewall_tenant_modes`).
- Shadow-timeline виджет на Dashboard (bar chart по inspector × day).

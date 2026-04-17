# bd-ShadowAI-8ir: примеры поведения режимов

Дата: 2026-04-17

Примеры иллюстрируют контракт PR-4. `payload` — `*firewall.Payload`,
`d` — возвращённый `*firewall.Decision`.

---

## Happy path 1: enforce-инспектор блокирует → shadow записывается

**Сценарий:** В pipeline два инспектора. `pi_stub` в shadow-режиме хочет
Flag, `dlp_block` в enforce хочет Block. shadow-наблюдение должно попасть
в `d.ShadowDecisions`, Block — в `d.Action`.

**Config:**
```
FIREWALL_MODE_DEFAULT=enforce
FIREWALL_MODE_PI_STUB=shadow
```

**Pipeline:**
```go
modes := firewall.LoadInspectorModesFromEnv()
p := firewall.NewPipelineWithModes(modes)
p.Register(flagInspector{name: "pi_stub"})     // shadow
p.Register(blockInspector{name: "dlp_block"})  // enforce
```

**Ожидание:**
- `d.Action == ActionBlock`
- `d.InspectorName == "dlp_block"`
- `d.ShadowDecisions == [{Inspector: "pi_stub", Action: Flag, ...}]`
- `payload.Meta["flagged"]` не установлен (shadow не мутирует)

**Метрика:**
```
shadowai_firewall_decisions_total{inspector="pi_stub",action="flag",mode="shadow"} 1
shadowai_firewall_decisions_total{inspector="dlp_block",action="block",mode="enforce"} 1
```

---

## Happy path 2: все инспекторы в shadow → запрос всегда allowed

**Сценарий:** Свежий deploy, три новых инспектора в shadow для
observation-only. Даже если все три хотят Block, handler должен пропустить
запрос и записать три shadow-наблюдения.

**Config:**
```
FIREWALL_MODE_DEFAULT=shadow
```

**Ожидание (при трёх inspector'ах, возвращающих Block):**
- `d.Action == ActionAllow`
- `d.ShadowDecisions` содержит 3 записи
- `audit_logs.policy_action == "allowed"` (фактический итог)
- `audit_logs.shadow_decisions_json` содержит JSON-массив из 3 объектов

---

## Edge case 1: disabled-инспектор не исполняется вообще

**Сценарий:** Инспектор `old_regex_scan` известен нестабильностью,
операционально отключен:

**Config:**
```
FIREWALL_MODE_OLD_REGEX_SCAN=disabled
```

**Pipeline:**
```go
p.Register(oldRegexScan{})  // mode=disabled резолвится автоматически
p.Register(piiInspector{})  // enforce
```

**Ожидание:**
- `oldRegexScan.InspectRequest` НЕ вызывается (счётчик вызовов == 0).
- Метрика `shadowai_firewall_decisions_total` для `inspector="old_regex_scan"`
  не инкрементится.
- `piiInspector` работает как обычно.

**Почему важно:** disabled эквивалентен "удалён из Register" — но без
правки кода. Для отключения на время инцидента:
```
kubectl set env deploy/shadowai FIREWALL_MODE_OLD_REGEX_SCAN=disabled
```

---

## Edge case 2: shadow Allow не пишется в ShadowDecisions

**Сценарий:** Инспектор `pii_classifier` в shadow. На большинстве
запросов возвращает Allow (ничего не нашёл).

**Ожидание:**
- Метрика инкрементится: `mode="shadow",action="allow"` — видимо operator'у
  как "shadow-инспектор отработал, не триггерил".
- `d.ShadowDecisions == []` — не раздуваем audit row шумом.
- `audit_logs.shadow_decisions_json == NULL`.

**Причина:** если бы Allow попадал в ShadowDecisions, каждая "чистая"
строка аудита несла бы `[{action: "allow"}]`. Это не сигнал, а шум.

---

## Failure case: невалидный FIREWALL_MODE_* → fallback на enforce

**Сценарий:** Оператор опечатался в env:
```
FIREWALL_MODE_PII=enfroce      # typo: "enfroce"
FIREWALL_MODE_DEFAULT=bloack   # typo
```

**Ожидание:**
- `LoadInspectorModesFromEnv()` возвращает:
  - `Default: ModeEnforce` (fallback для невалидного значения)
  - `Overrides: {}` (невалидный override пропускается тихо)
- `pii` резолвится в `ModeEnforce` через default.
- Приложение запускается без ошибок.
- Оператор видит misconfig через `GET /proxy/firewall/status`:
  все инспекторы показывают `mode="enforce"`, хотя ожидалось `shadow`
  для `pii`.

**Почему не fail-fast:** жёсткая остановка при опечатке в non-critical
env — плохой UX. Видимый misconfig в `/status` + pre-deploy проверка в CI
лучше, чем Pod CrashLoop на prod.

---

## Observability example: разбор audit row

**Реальная запись audit_logs после запроса с shadow-инспектором:**

```json
{
  "id": "af8...",
  "user_id": "u-42",
  "model": "gpt-4o",
  "provider": "openai",
  "endpoint": "v1/chat/completions",
  "status_code": 200,
  "policy_action": "allowed",
  "shadow_decisions_json": [
    {
      "inspector": "prompt_injection",
      "action": "flag",
      "reason": "heuristic match: ignore_instructions",
      "severity": "medium"
    },
    {
      "inspector": "content_moderation",
      "action": "block",
      "reason": "judge: toxicity=0.83",
      "severity": "high"
    }
  ],
  "duration_ms": 420
}
```

**Интерпретация:**
- Запрос прошёл (`status_code=200`, `policy_action="allowed"`).
- Два shadow-инспектора сработали:
  - `prompt_injection` (flag) — heuristic триггернул, но в shadow.
  - `content_moderation` (block) — judge счёл toxicity высокой,
    но в shadow.
- Enforce-инспекторы (pii, policy, dlp) ничего не сказали → запрос
  пропущен.
- Оператор видит сигнал: если `content_moderation` выйдет из shadow
  в enforce, этот конкретный запрос будет заблокирован. Решение принимается
  по данным, а не на авось.

**SQL-разрез по popular shadow-действиям за сутки:**

```sql
SELECT
  e->>'inspector' AS inspector,
  e->>'action'    AS action,
  count(*)        AS observations
FROM audit_logs,
     jsonb_array_elements(shadow_decisions_json) AS e
WHERE created_at > now() - interval '24 hours'
GROUP BY 1, 2
ORDER BY observations DESC;
```

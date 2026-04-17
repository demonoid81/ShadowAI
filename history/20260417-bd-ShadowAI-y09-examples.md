# bd-ShadowAI-y09: примеры UX и поведения UI

**Дата:** 2026-04-17

## Happy path 1: оператор открывает FirewallPage с смешанной конфигурацией

**Config:**
```
FIREWALL_MODE_DEFAULT=enforce
FIREWALL_MODE_PII=shadow
FIREWALL_MODE_CONTENT_RATELIMIT=disabled
```

**UI рендерит 10 строк, каждая с 3 badge'ами:**
- `pii`: `[request]` `[enforce серый]` → нет, `[shadow жёлтый]` ← эта
  строка заметна на глаз, оператор видит "наблюдаем, но не блокируем".
- `content_ratelimit`: `[request]` `[disabled тёмный]`
  `[Enabled/Disabled зелёный или серый]` ← двойной индикатор
  "инспектор сконфигурирован, но операционно off".
- Остальные 8: `[phase]` `[enforce серый]` `[Enabled зелёный]` —
  стандартный режим, не шумит визуально.

Без PR-4.1 все 10 строк выглядели бы идентично; оператор не отличил бы
shadow-инспектор от enforce.

---

## Happy path 2: аналитик фильтрует audit logs на shadow-события

**Сценарий:** за прошедшие сутки накопилось ~50k audit записей.
Аналитик хочет посмотреть только те, где shadow-инспекторы что-то
видели — чтобы оценить, сколько и каких сработок будет после
promote'а shadow → enforce.

**UI:**
- AuditLogPage → dropdown `Shadow`: выбрать `With shadow`.
- Query to backend: `GET /audit/logs?has_shadow=yes&limit=50`.
- Backend: `AND shadow_decisions_json IS NOT NULL`.
- Таблица показывает только те записи; в колонке Shadow — badge
  `shadow (N)`.
- Клик на `shadow (2)` → модалка:
  ```json
  [
    {
      "inspector": "prompt_injection",
      "action": "flag",
      "reason": "heuristic: ignore_instructions",
      "severity": "medium"
    },
    {
      "inspector": "content_moderation",
      "action": "block",
      "reason": "judge: toxicity=0.83",
      "severity": "high"
    }
  ]
  ```

Без PR-4.1 аналитик писал бы SQL напрямую.

---

## Edge case 1: malformed shadow_decisions_json не ломает таблицу

**Сценарий:** по какой-то причине (баг в backend / ручная правка БД)
одна запись имеет невалидный JSON в `shadow_decisions_json`:
`{"not": "an array"}`.

**UI:**
- `ShadowCell.vue` ловит parse failure или "не массив" → рендерит
  красный badge `invalid shadow payload` вместо `shadow (N)`.
- Остальные строки таблицы рендерятся нормально.
- Клик на invalid badge → модалка показывает **raw text** +
  предупреждение "invalid shadow payload".

**Почему важно:** оператор получает сигнал о data corruption вместо
того, чтобы страница падала с runtime error.

---

## Edge case 2: пустой has_shadow в URL

**Сценарий:** пользователь нажимает Prev/Next, AuditLogPage сохраняет
filters с `has_shadow: ''`. Query должна не содержать этот параметр
вообще (иначе `?has_shadow=` протекает к backend).

**Ожидание (PR-4.1):**
- `load()` отсекает пустые значения через
  `for ([k,v] of Object.entries(filters)) if (v) params[k] = v`.
- Query-string: `?offset=50&limit=50` — без лишнего `has_shadow=`.
- Backend видит отсутствие параметра → `""` → no-op в repository.

---

## Failure case: мусор в has_shadow от legacy клиента

**Сценарий:** кто-то запускает старый bash-скрипт с
`curl /audit/logs?has_shadow=1`.

**Ожидание:**
- Handler whitelist (`yes|no` → OK, иначе `""`) нормализует `"1"` → `""`.
- Repository не добавляет лишний WHERE.
- Response — обычный список logs (как без фильтра).
- Сервер не возвращает 400 (fail-safe для обратной совместимости).

Покрывается тестом `TestAuditHandler_HasShadow_Whitelist`.

---

## UI визуальная проверка: enforce-badge не шумит

**Сценарий:** операторов беспокоит, что добавление mode-badge сделает
FirewallPage перегруженной.

**Ожидание (PR-4.1):**
- enforce badge — нейтральный серый `bg-dark-700 text-gray-300`,
  размер `text-xs`, padding `py-0.5 px-2`, font-mono.
- Визуально сливается с существующим phase-label (тоже серый).
- shadow badge — жёлтый, отчётливо выделяется на тёмной странице.
- disabled badge — тёмно-серый с приглушённым текстом, не привлекает
  внимания (корректно: disabled = "ничего не происходит").

Итог: обычный оператор смотрит страницу → видит 8 серых enforce-badge'ев
в ряд (как фон) + 1 жёлтый shadow → взгляд сразу ловит исключение.

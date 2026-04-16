# bd-ShadowAI-h2o: Обработка ActionSanitize и ActionFlag в proxy handler

## Контекст

В `backend/internal/proxy/handler.go` все 6 точек вызова `firewall.Pipeline`
(3 request + 3 response, по 3 для provider-specific chat и UnifiedChat)
реагировали только на `firewall.ActionBlock`. Решения пайплайна с действием
`ActionFlag` или `ActionSanitize` фактически игнорировались — pipeline их
возвращал, но handler не делал с ними ничего.

Это противоречит семантике новой firewall-пайплайн-архитектуры, где
инспекторы могут возвращать три "не-разрешающих" действия:

- `ActionBlock` — полный отказ (уже работал),
- `ActionSanitize` — очистить текст и продолжить,
- `ActionFlag` — зафиксировать инцидент в аудите, но продолжить.

## Цель

1. Расширить `firewall.Decision` полем `SanitizedText` (заполняется
   инспектором при `ActionSanitize`).
2. В `DLPInspector.inspect()` вычислять и возвращать санитизированный текст
   при `ActionSanitize`.
3. В pipeline `run()` сохранять `SanitizedText` при обновлении "худшего"
   действия и возвращать его в финальном Decision.
4. Handler: во всех 6 точках реагировать на `ActionFlag` (audit с
   `PolicyAction="warned"`) и `ActionSanitize` (подменять downstream-текст).

## Scope

### In

- `backend/internal/firewall/firewall.go` — поле `SanitizedText` в `Decision`,
  проброс в `run()`.
- `backend/internal/firewall/dlp_inspector.go` — вызов `svc.Sanitize()` при
  `ActionSanitize` и запись в `result.SanitizedText`.
- `backend/internal/firewall/dlp_inspector_test.go` — тест
  `TestDLPInspector_SanitizePopulatesText`.
- `backend/internal/proxy/handler.go` — все 6 точек: добавлены обработчики
  `ActionFlag` (audit warned) и `ActionSanitize` (подмена downstream текста).

### Out

- Остальные инспекторы (PII, Jailbreak, ContentModeration, PolicyInspector,
  OutputValidation, Semantic, Judge) — их поведение не меняется; они и так
  возвращают либо `ActionAllow`, либо `ActionBlock`. Если в будущем какой-то
  из них начнёт возвращать `ActionSanitize`, он обязан будет сам заполнить
  `SanitizedText`.
- Формат аудита и контракт API — не меняются (используются существующие
  поля `AuditLog`).

## Реализация (по шагам)

1. `firewall.Decision`: добавлено поле `SanitizedText string` с тегом
   `json:"sanitized_text,omitempty"`.
2. `Pipeline.run()`: объявлена локальная переменная `finalSanitizedText`,
   копируется из `d.SanitizedText` при обновлении `finalAction` и
   прокидывается в итоговый `&Decision{...}`.
3. `DLPInspector.inspect()`: перед `return` строится `result`, и при
   `action == ActionSanitize` вызывается `d.svc.Sanitize(text, piiFindings)`
   и записывается в `result.SanitizedText`.
4. `handler.go`, 6 точек:
   - **Request (provider-specific, ~216)** — после блока ActionBlock
     добавлены ветки ActionFlag (аудит с PolicyAction="warned",
     StatusCode=200) и ActionSanitize (`allText = fwDecision.SanitizedText`).
     `bodyBytes` не трогается — существующий DLP-путь санитизирует
     `requestPayload` ниже по коду.
   - **Response streaming (provider-specific, ~379)** — после блока
     ActionBlock: ActionFlag → audit warned с response body;
     ActionSanitize → `accumulated = fwDecision.SanitizedText` и
     `respBytes = []byte(accumulated)`.
   - **Response non-streaming (provider-specific, ~466)** — те же две ветки:
     audit warned и `respBody = []byte(fwDecision.SanitizedText)`.
   - **Request (UnifiedChat, ~1099)** — зеркало request provider-specific,
     но с Provider="unified" и Endpoint="/proxy/chat".
   - **Response streaming (UnifiedChat, ~1300)** — зеркало
     response-streaming provider-specific, но с candidate.Name и
     "/proxy/chat".
   - **Response non-streaming (UnifiedChat, ~1410)** — зеркало
     response-non-streaming, аналогично.

## Размышления

- Рассмотрен вариант мутации `bodyBytes` при ActionSanitize в request-пути,
  но отклонён: санитизированный `SanitizedText` — это свободный текст,
  который невозможно надёжно вставить обратно в JSON-тело запроса
  без знания схемы. Существующий DLP-путь уже работает с `requestPayload`
  через `h.dlpSvc.Sanitize(string(bodyBytes), findings)` и безопасно
  обрабатывает байты тела.
- Альтернатива "жёстко падать на ActionSanitize без SanitizedText"
  отклонена — это ломает обратную совместимость с инспекторами, которые
  могут ещё не поддерживать SanitizedText. Принято решение: проверять
  `fwDecision.SanitizedText != ""`.
- Для ActionFlag в аудите принято решение использовать
  `PolicyAction = "warned"` и `StatusCode = 200`, чтобы аналитика могла
  отличить "warned" от "blocked".
- `p.recordFlag()` для ContentRateLimiter продолжает работать как раньше —
  он вызывается в `Pipeline.run()`, независимо от хендлера.

## Примеры поведения

См. `20260415-bd-ShadowAI-h2o-examples.md`.

## Проверка

- `go build ./cmd/shadowai` — проходит.
- `go test ./... -count=1` — все тесты зелёные (auth, config, dlp, firewall,
  internaldb, middleware, pii, policy, proxy).
- Новый тест `TestDLPInspector_SanitizePopulatesText` — PASS, не skipped.

## Риски / зависимости

- **Риск**: инспекторы, возвращающие ActionSanitize без SanitizedText,
  попадут в ветку "sanitize" без подмены текста. Митигация: handler
  проверяет `fwDecision.SanitizedText != ""` и не трогает буферы без
  непустого значения — поведение деградирует до "прозрачного прохода",
  что безопасно.
- **Риск**: дублирование записей в audit при сочетании
  "firewall.ActionFlag + dlp-block далее по пайплайну" — handler в
  таком случае запишет два лога ("warned" + "blocked"). Принято
  как допустимое: оба события реально произошли.

## Допущения

- `StatusCode = 200` и `PolicyAction = "warned"` — уместная семантика
  для аудита при non-blocking-событиях; не конфликтует с существующими
  индексами/дашбордами (видно по отсутствию валидации PolicyAction в
  `domain.AuditLog`).

## Roadmap

### v1 (сделано)

- SanitizedText в Decision.
- DLPInspector заполняет SanitizedText.
- Handler обрабатывает ActionFlag и ActionSanitize в 6 точках.

### v2+

- Интеграционный тест для handler: пропустить ActionFlag-решение через
  полный pipeline и убедиться, что audit-запись "warned" создаётся
  (сейчас покрыто только unit-тестом DLPInspector).
- Поддержка SanitizedText в других инспекторах (output validation,
  content moderation) — если появится реальный сценарий очистки
  ответа модели от запретных фрагментов.
- Явная семантика "how many ActionFlag в одном pipeline → один audit"
  — сейчас handler пишет один лог на pipeline-решение, что соответствует
  "worst action"-логике pipeline.run().

## History

- Plan: history/20260415-bd-ShadowAI-h2o-firewall-actions.md (этот файл)
- Examples: history/20260415-bd-ShadowAI-h2o-examples.md

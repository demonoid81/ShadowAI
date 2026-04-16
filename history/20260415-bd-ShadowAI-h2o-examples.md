# bd-ShadowAI-h2o: Примеры поведения

## 1. Happy path — ActionAllow (ничего не изменилось)

**Вход (request)**: `"Привет, сгенерируй план на неделю"` — нет PII, нет
секретов, никаких инспекторов.

**Pipeline.run()**:
- DLPInspector → `{Action: ActionAllow, Findings: nil}`
- остальные инспекторы → `ActionAllow`

**Decision**: `{Action: "allow", SanitizedText: ""}`

**Handler**: ни одна из веток ActionBlock / ActionFlag / ActionSanitize
не сработала → обычный проход к провайдеру. Аудит пишет штатный
`"allowed"` запись в конце.

## 2. Happy path — ActionSanitize для email (новое поведение)

**Вход (request)**: `"мой email user@example.com, помоги с промптом"`.

**DLPInspector.inspect**:
- `pii.Scan` находит email → Finding `{Type: "email", Severity: medium}`
- `svc.Evaluate(text, piiFindings)` возвращает
  `{Action: DLPActionSanitize, Reason: "medium-risk sensitive data redacted: email"}`
- маппинг → `action = ActionSanitize`
- `action == ActionSanitize` → вызывается
  `result.SanitizedText = d.svc.Sanitize(text, piiFindings)` →
  `"мой email [redacted:email], помоги с промптом"`

**Pipeline.run()**:
- DLPInspector вернул `{Action: ActionSanitize, SanitizedText: "мой email [redacted:email], помоги с промптом"}`
- `compareAction(sanitize, allow) = 2 > 0` → `finalAction = sanitize`,
  `finalSanitizedText = "мой email [redacted:email], ..."`
- Остальные инспекторы возвращают ActionAllow, не перезаписывают.

**Decision**:
`{Action: "sanitize", SanitizedText: "мой email [redacted:email], ...", Findings: [...]}`

**Handler (request site)**:
- `fwDecision.Action == firewall.ActionBlock` → false
- `fwDecision.Action == firewall.ActionFlag` → false
- `fwDecision.Action == firewall.ActionSanitize && SanitizedText != ""`
  → true → `allText = fwDecision.SanitizedText`
- Дальнейшие проверки (policy, budget, provider) идут по очищенному
  тексту; `bodyBytes` остаётся исходным (sanitize для JSON-тела делает
  существующий DLP-путь ниже).

## 3. Edge — ActionFlag от ContentRateLimiter (новое поведение)

**Вход (request)**: серия одинаковых подозрительных запросов от одного
юзера триггерит ContentRateLimiter на ActionFlag.

**Pipeline.run()**:
- DLPInspector → ActionAllow.
- ContentRateLimiter → `{Action: ActionFlag, Reason: "too many flagged ..."}`
- `p.recordFlag(userID)` вызывается (внутренний счётчик).
- `compareAction(flag, allow) = 1 > 0` → `finalAction = flag`,
  `finalInspectorName = "content_ratelimit"`.

**Decision**: `{Action: "flag", SanitizedText: "", InspectorName: "content_ratelimit"}`

**Handler (request site)**:
- ActionBlock → false.
- ActionFlag → true → `h.auditSvc.Log(&AuditLog{PolicyAction: "warned", StatusCode: 200, ...})`.
- ActionSanitize → false.
- Обработка продолжается штатно (не блокируется!).

**Результат**: юзер получает нормальный ответ, но в audit появляется
запись "warned" с тэгом inspector="content_ratelimit".

## 4. Edge — ActionSanitize без SanitizedText (защитная ветка)

**Вход**: гипотетический инспектор вернул `{Action: ActionSanitize}`
но забыл заполнить `SanitizedText`.

**Pipeline.run()**: `finalAction = sanitize`, `finalSanitizedText = ""`.

**Handler**:
- `fwDecision.Action == firewall.ActionSanitize && fwDecision.SanitizedText != ""`
  → false (SanitizedText пустой).
- Handler **не трогает** `allText` / `accumulated` / `respBody`.

**Результат**: поведение деградирует до ActionAllow — безопасный
прозрачный проход. Лог "warned" в этом случае не пишется (это не
flag, а sanitize без данных).

## 5. Failure — ActionBlock остаётся приоритетнее всего (regression guard)

**Вход (request)**: `"sk-abcdefghij1234567890abcdef1234567890abcdefg"`
(OpenAI API key).

**DLPInspector.inspect**:
- `svc.Evaluate` → `{Action: DLPActionBlock, Reason: "high-risk secret leak signals: openai_api_key"}`
- маппинг → `ActionBlock`.
- `action == ActionSanitize` → false, `SanitizedText` остаётся пустым.

**Pipeline.run()**:
- DLPInspector вернул `{Action: ActionBlock}` → `d.Findings = allFindings`
  и немедленный `return d, nil`. Остальные инспекторы не выполняются.

**Decision**: `{Action: "block", Reason: "high-risk secret leak signals: openai_api_key"}`

**Handler (request site)**:
- `fwDecision.Action == firewall.ActionBlock` → true → audit "blocked",
  HTTP 403, JSON `{"error":"blocked by firewall",...}`, `return`.
- Ветки ActionFlag / ActionSanitize не срабатывают (return выше).

**Результат**: обратная совместимость полностью сохранена, ActionBlock
работает ровно как раньше.

## 6. Edge — Response streaming с ActionSanitize (новое поведение)

**Вход (response stream)**: LLM начал выдавать в ответе
`"ваш пароль admin123"` (условно, DLP считает это medium-risk).

**Handler (streaming response site)**:
- `io.ReadAll(resp.Body)` → `respBytes`.
- `accumulated = string(respBytes)`.
- Pipeline.InspectResponse → `{Action: ActionSanitize, SanitizedText: "ваш пароль [redacted:password]"}`.
- `fwDecision.Action == firewall.ActionSanitize && SanitizedText != ""` →
  true → `accumulated = fwDecision.SanitizedText` и
  `respBytes = []byte(accumulated)`.
- Далее `pii.Scan(accumulated)`, `dlp.Evaluate(accumulated, ...)`,
  `responsePayload = ...` — всё по очищенному тексту.
- Клиент получает очищенный ответ (HTTP 200 с провайдерскими хэдерами).

**Результат**: sanitize действительно мутирует downstream-данные,
что и было целью фикса.

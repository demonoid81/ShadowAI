# PR-G1 Examples

Примеры поведения Provider/Model Governance в разных сценариях.

## Happy paths (2)

### Example 1: Allow для known (provider, model) pair

**Setup:**
```json
{
  "mode": "allowlist_strict",
  "rules": [
    {"provider": "openai", "models": ["gpt-4o", "gpt-4o-mini"]},
    {"provider": "anthropic", "models": ["claude-3-opus"]}
  ]
}
```

**Request:** `POST /proxy/openai/v1/chat/completions`
```json
{"model": "gpt-4o", "messages": [...]}
```

**Result:**
- Evaluate → `{Kind: Allow, Code: "allowed", PolicyID: "p-1"}`
- Proxy продолжает обычный flow: firewall → DLP → budget → forward.
- admin_event_logs: запись НЕ создаётся (deny-only event в v1).

### Example 2: Mode=disabled — governance не применяется

**Setup:**
```json
{"mode": "disabled", "rules": []}
```

**Request:** любой (provider, model).

**Result:**
- Evaluate → `{Kind: Allow, Code: "governance_disabled", PolicyID: "p-1"}`
- Proxy продолжает flow без короткозамыкания.
- Оператор видит в GET `/api/governance/policy`, что есть политика,
  но она в disabled-state — удобно для quick-enable без
  пересоздания правил.

## Edge cases (2)

### Example 3: Empty Rules при allowlist_strict → deny-all

**Setup:**
```json
{"mode": "allowlist_strict", "rules": []}
```

**Request:** любой (provider, model).

**Result:**
- Evaluate → `{Kind: Deny, Code: "unknown_provider"}`
- 403 + admin_event:
  ```json
  {
    "action": "policy_deny",
    "resource": "provider_model",
    "target_id": "openai/gpt-4o",
    "metadata": {"code":"unknown_provider","policy_id":"p-1",...}
  }
  ```
- Оператор понимает: политика активна, но ни одно правило не
  прописано — это сознательный «lock down» (fail-closed).

### Example 4: Provider в allowlist, конкретная model — нет

**Setup:**
```json
{
  "mode": "allowlist_strict",
  "rules": [{"provider":"openai","models":["gpt-4o-mini"]}]
}
```

**Request:** `POST /proxy/openai/v1/chat/completions` с
`{"model":"gpt-4o"}`.

**Result:**
- Evaluate находит провайдера openai, но модель gpt-4o не в списке.
- Decision: `{Kind: Deny, Code: "unknown_model",
  Reason: "модель \"gpt-4o\" не в allowlist провайдера \"openai\""}`
- 403 + admin_event с code=unknown_model.

Это ключевая per-model гранулярность: оператор может разрешить
только дешёвые/compliant модели у одного провайдера и запретить
дорогие/experimental.

## Failure case (1)

### Example 5: Repository unreadable → fail-closed

**Setup:** PG connection drop / tx timeout при чтении active policy.

**Request:** любой.

**Result:**
- `repo.GetActive` возвращает error.
- Service возвращает `Decision{Kind: Deny, Code: "policy_read_failure",
  Reason: "не удалось прочитать governance-политику — fail-closed"}`.
- Proxy: 403 + admin_event с code=policy_read_failure.
- Caller видит non-nil error в Decision return — можно залогировать
  полный root cause (сама Decision его не экспонирует, чтобы не
  leak'ать internals в HTTP body).

Это критично для compliance: если control не работает, безопаснее
отказать, чем пропустить. Fail-open для availability недопустим
в governance-контексте.

## Case-insensitive matching (bonus)

Provider/model идентификаторы нечувствительны к регистру.

**Setup:**
```json
{"mode":"allowlist_strict","rules":[
  {"provider":"OpenAI","models":["GPT-4"]}
]}
```

**Request:** `{"model":"gpt-4"}` на `/proxy/openai/...`.

**Result:** Allow. EqualFold снимает класс ошибок «OpenAI vs openai»
и «GPT-4 vs gpt-4» без необходимости нормализации на стороне
оператора.

## UnifiedChat behaviour

Для `/proxy/chat` (unified routing) governance применяется как фильтр:

**Setup:**
```json
{"mode":"allowlist_strict","rules":[
  {"provider":"openai","models":["gpt-4o"]}
]}
```

Router вернул candidates: `[openai, anthropic, gemini]`.

**Governance filter:**
- openai/gpt-4o → Allow → остаётся в кандидатах.
- anthropic/... → Deny (unknown_provider) → убирается.
- gemini/... → Deny (unknown_provider) → убирается.

**Result:** candidates=[openai], fallback loop работает как прежде.

Если governance отфильтровал все: 403 с representative deny
(первый denied candidate) + admin_event.

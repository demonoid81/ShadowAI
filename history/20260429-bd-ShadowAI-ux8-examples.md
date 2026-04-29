# bd ShadowAI-ux8 — примеры

## Happy path 1 — strict allowlist

1. Admin открывает `/policies`.
2. UI загружает active governance policy через `GET /api/governance/policy`.
3. Admin выбирает mode `allowlist_strict`.
4. Добавляет provider `openai` и models `gpt-4, gpt-4o`.
5. Нажимает save.

Ожидаемый результат: UI отправляет normalized payload с lowercase provider/model и после ответа backend показывает сохранённую policy.

## Happy path 2 — context_scoped rule

1. Admin выбирает mode `context_scoped`.
2. Добавляет rule `department=finance`, `role=analyst`, sensitivity `confidential`.
3. В rule добавляет provider `openai`, model `gpt-4`.
4. Нажимает save.

Ожидаемый результат: workflow не требует raw JSON; backend validation остаётся final source of truth.

## Edge case 1 — duplicate provider/model entries

1. Admin вводит `OpenAI` и models `GPT-4, gpt-4, GPT-4O`.
2. UI normalized preview показывает один provider `openai` и deduplicated models.

Ожидаемый результат: payload не содержит duplicate provider/model records.

## Edge case 2 — role_based без role rules

1. Admin выбирает mode `role_based`.
2. Не добавляет role rules.
3. UI показывает pre-save warning `role_based_without_roles`.

Ожидаемый результат: UI явно предупреждает о deny-by-default риске, но не подменяет backend validation.

## Failure case — backend validation error

1. Admin применяет JSON fallback с `context_scoped` и пустым `context_rules`.
2. Backend возвращает 400 validation error.
3. UI показывает backend error string в error banner.

Ожидаемый результат: ошибка не скрывается, policy не считается сохранённой.

# bd-ShadowAI-9ch — примеры исправленных формулировок

## Успешный сценарий 1: evidence integrity questionnaire

Вопрос: “Do you support key rotation for tamper-evident audit evidence?”

Корректный ответ: “Yes, verifier supports chain/signing keyrings and restore drill automation. Rotation execution and evidence retention are operator-owned.”

## Успешный сценарий 2: independent anchor witness

Вопрос: “Can evidence anchors be written to more than one sink?”

Корректный ответ: “Yes, W8 supports additional independent sinks. Operators must configure them; single-sink deployments have weaker witness independence.”

## Крайний случай 1: BYOK scope

Вопрос: “Is all data encrypted with customer-managed keys?”

Корректный ответ: “No. BYOK2 covers audit request/response payloads through Vault Transit and BYOK2.1 covers legacy sweep. Non-audit classes remain roadmap.”

## Крайний случай 2: restore drill

Вопрос: “Is restore verification fully hands-off?”

Корректный ответ: “The command is automated through `audit-verify --restore-drill`, but scheduling and retention of drill evidence remain operator-owned.”

## Отказ 1: certification overstatement

Запрещённый ответ: “ShadowAI is SOC2/ISO certified.”

Ожидание: документы сохраняют явный disclaimer: mapping is not certification.

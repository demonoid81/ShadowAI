# bd-ShadowAI-5yr — примеры BYOK sweep

## Успешный сценарий 1: plaintext request

Вход: строка `audit_logs` содержит `request_body="legacy prompt"`, `response_body=""`.

Ожидание: sweep шифрует только `request_body`, `response_body` остаётся пустым.

## Успешный сценарий 2: mixed plaintext/envelope

Вход: `request_body` plaintext, `response_body` уже валидный `byok:v1` envelope.

Ожидание: шифруется только `request_body`; `response_body` не double-encrypt.

## Крайний случай 1: пустые поля

Вход: оба payload поля NULL или empty string.

Ожидание: строка не меняется.

## Крайний случай 2: invalid BYOK prefix

Вход: payload начинается с `byok:v1:`, но envelope невалиден.

Ожидание: значение считается plaintext и шифруется, чтобы пользовательский literal не обходил BYOK.

## Отказ 1: KMS недоступен

Вход: Vault Transit возвращает ошибку во время batch.

Ожидание: sweep возвращает runtime error и не делает plaintext fallback.

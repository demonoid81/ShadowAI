# bd-ShadowAI-rhl.4 — примеры BYOK2

## Успешный сценарий 1: запись через Vault Transit

Вход: `BYOK_ENABLED=true`, `BYOK_PROVIDER=vault_transit`, валидные `BYOK_VAULT_ADDR`, `BYOK_VAULT_TOKEN`, `BYOK_VAULT_KEY_NAME`; audit row содержит `request_body="prompt"`.

Ожидание: repository вызывает Vault Transit `/v1/transit/encrypt/<key>`, сохраняет `byok:v1:<base64-json-envelope>` вместо открытого текста.

## Успешный сценарий 2: dual-read зашифрованной строки

Вход: `audit_logs.response_body` уже содержит BYOK envelope, приложение стартовало с тем же Vault key.

Ожидание: `audit.Repository.List` возвращает caller'у расшифрованный response body; WORM verifier не требует decrypt, потому что payload не входит в canonical row hash.

## Крайний случай 1: legacy строка с открытым текстом

Вход: старая строка до BYOK rollout хранит открытый `request_body`.

Ожидание: read path оставляет plaintext без ошибки. Это нужно для new-writes-only rollout без background sweep.

## Крайний случай 2: пустое тело

Вход: `request_body=""` или `response_body=""`.

Ожидание: encryptor не вызывается; пустая строка остаётся пустой, чтобы не менять semantics scrubbed/empty payload.

## Крайний случай 3: payload начинается с BYOK-prefix

Вход: пользовательский prompt начинается с `byok:v1:`.

Ожидание: write path всё равно шифрует payload. Prefix не считается trusted marker на write path, иначе пользователь мог бы обойти BYOK шифрование.

## Отказ 1: KMS недоступен при записи

Вход: BYOK включён, Vault Transit возвращает 503.

Ожидание: audit insert fail-closed возвращает ошибку; payload не записывается plaintext fallback'ом.

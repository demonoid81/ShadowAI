# bd-ShadowAI-rhl.4 — BYOK2 KMS-backed payload encryption

## Контекст

BYOK1 был зафиксирован как design-only RFC: WORM chain/anchors доказывали целостность audit evidence, но `audit_logs.request_body` и `audit_logs.response_body` оставались plaintext при `AUDIT_PAYLOAD_MODE=full` или redacted-body сценариях. Это confidentiality gap для enterprise/security questionnaires.

CASS недоступен: `cass health` вернул `index stale`. Источники истины для реализации: фактический код, BYOK1 RFC, bd-задача `ShadowAI-rhl.4`.

## Допущения

- Первый production backend: HashiCorp Vault Transit.
- Поля v1: `audit_logs.request_body` и `audit_logs.response_body`.
- Модель rollout: new-writes-only + dual-read. Фоновый sweep старых строк не входит в v1.
- Static AES-GCM backend разрешён только для dev/test wiring; prod validation требует `vault_transit`.

## Размышления

Рассмотрены варианты:

- DEK envelope с wrap/unwrap через KMS и хранением wrapped DEK metadata.
- Прямое Vault Transit encrypt/decrypt для каждого payload field.
- DB-level encryption без application envelope.

Принято решение: v1 использует self-describing application envelope и Vault Transit как KMS-backed encrypt/decrypt backend. Это закрывает payload confidentiality без schema rewrite и сохраняет WORM invariant: canonical HMAC считается до шифрования payload fields и не требует KMS для verification.

Альтернатива с per-tenant DEK wrapping отклонена для v1: она требует отдельной схемы хранения wrapped DEK/epoch metadata и rotation workflow. Это переносится в v2+, чтобы не смешивать confidentiality rollout с key lifecycle migration.

## План реализации

1. Добавить `internal/byok`: envelope encode/decode, AES-GCM dev/test encryptor, Vault Transit encryptor.
2. Встроить optional payload encryptor в `audit.Repository`: write encrypts request/response, read decrypts envelopes and leaves plaintext legacy rows unchanged.
3. Добавить config/env guards: `BYOK_ENABLED`, `BYOK_PROVIDER`, `BYOK_VAULT_*`, dev/test static key.
4. Подключить wiring в `cmd/shadowai`.
5. Добавить migration marker и обновить документы, где BYOK был описан как отсутствующий.
6. Прогнать targeted и full tests, закрыть bd, сделать commit.

## Roadmap

### v1

- Vault Transit KMS-backed payload encryption для audit request/response fields.
- Dual-read plaintext/envelope.
- WORM verification без KMS.

### v2+

- Per-tenant DEK wrapping/epoch storage.
- Background re-encryption sweep для legacy rows.
- BYOK-aware evidence bundle metadata.
- Legal hold selector/payload encryption.
- Customer KMS backends beyond Vault Transit.

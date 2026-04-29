# Примеры BYOK3

## Happy path 1 — новый write использует active epoch

Условия:

- `BYOK_ENABLED=true`
- `BYOK_EPOCHS_REQUIRED=true`
- `byok_key_epochs` содержит `org-a`, `kid=tenant:org-a:dek:2026-Q2`, `status=active`

Ожидаемый результат:

- `audit_logs.request_body` и `response_body` сохраняются как BYOK envelope.
- Envelope содержит `kid=tenant:org-a:dek:2026-Q2`, `org_id=org-a`, `provider_kid=vault:transit/audit-key`.
- WORM `row_hash` не меняет semantics, потому что payload не входит в canonical.

## Happy path 2 — rotation без downtime

Условия:

- Старые rows имеют `kid=tenant:org-a:dek:2026-Q1`, status `retired`.
- Новый active epoch: `kid=tenant:org-a:dek:2026-Q2`.

Ожидаемый результат:

- Новые writes используют Q2.
- Старые rows decrypt-ятся по Q1, потому что decrypt lookup идёт по envelope `kid`, а не по active epoch.

## Edge case 1 — legacy BYOK2 envelope

Условия:

- Row содержит BYOK2 envelope без `org_id` и `provider_kid`.

Ожидаемый результат:

- `EpochEncryptor` делегирует decrypt во внутренний encryptor.
- Backward compatibility сохраняется для существующих encrypted rows.

## Edge case 2 — tenant bundle metadata

Условия:

- Bundle export видит encrypted request/response payload envelopes.

Ожидаемый результат:

- `bundle_manifest.json.encrypted_fields` содержит `audit_logs.request_body` / `audit_logs.response_body`.
- `bundle_manifest.json.key_epochs` содержит только non-secret summary: `org_id`, `kid`, `provider`, `provider_kid`, `status`, `field_count`.
- KMS token, plaintext key, wrapped key и payload plaintext не экспортируются.

## Failure case — no active epoch in enforce mode

Условия:

- `BYOK_EPOCHS_REQUIRED=true`.
- Для `org-a` нет active epoch.

Ожидаемый результат:

- Audit payload write возвращает controlled error `BYOK active DEK epoch not found`.
- Plaintext fallback не происходит.

## Failure case — cross-tenant envelope

Условия:

- Envelope содержит `kid=tenant:org-a:dek:2026-Q1`, но `org_id=org-b`.

Ожидаемый результат:

- Decrypt rejected как cross-tenant mismatch.
- Payload не раскрывается.

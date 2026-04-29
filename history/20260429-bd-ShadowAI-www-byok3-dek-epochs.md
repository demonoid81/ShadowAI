# Задача

`ShadowAI-www` — BYOK3: tenant DEK epochs and key lifecycle.

# Контекст

Roadmap после OPS2-OPS4 выбрал BYOK3 как следующий product/security track. BYOK2/BYOK2.1 уже закрыли Vault Transit encryption для `audit_logs.request_body` и `audit_logs.response_body`, а также operator sweep для legacy plaintext rows.

Оставшийся gap: encrypted payload есть, но key lifecycle не был first-class capability. Не хватало persistent epoch metadata, rotation semantics, operator-visible state и bundle-level summary.

# План

1. Подтвердить текущий BYOK2 код: envelope, encryptor interface, audit repository hooks, sweep CLI, bundle manifest.
2. Добавить red tests для epoch wrapper и bundle metadata.
3. Реализовать BYOK epoch domain:
   - status dictionary;
   - `EpochStore`;
   - `EpochEncryptor`;
   - SQL-backed `EpochRepository`.
4. Добавить migration `023_byok_key_epochs.sql`.
5. Подключить epoch wrapper в `shadowai` BYOK wiring.
6. Добавить operator CLI `audit-byok-epochs`.
7. Добавить bundle manifest metadata: `encrypted_fields`, `key_epochs`.
8. Обновить build gates: Makefile, CI, Dockerfile.
9. Обновить roadmap/history и выполнить проверки.

# Размышления

Рассмотрены два варианта реализации.

Вариант полного BYOK platform с HSM/AWS/GCP/Azure abstraction отклонён как преждевременный: BYOK1 RFC прямо оставляет provider-specific backends за рамками текущего этапа.

Принято решение реализовать BYOK3 v1 как lifecycle layer поверх существующего BYOK2 encryptor interface. Это сохраняет Vault Transit/static AES-GCM provider model, не меняет WORM canonical и не требует KMS для evidence verification.

Рассмотрен вариант принудительно требовать active epoch всегда при `BYOK_ENABLED=true`. Он отклонён как слишком резкий для upgrade path. Вместо этого добавлен `BYOK_EPOCHS_REQUIRED`: при `true` no active epoch fail-closed, при `false` активные epochs используются если есть, а legacy BYOK2 envelope path остаётся допустимым для постепенного rollout.

Рассмотрен вариант re-encrypt старые rows при каждой rotation. Он отклонён для v1: rotation metadata должна позволять mixed epochs, а bulk re-encryption остаётся отдельным операторским действием.

# Реализация

Добавлено:

- `backend/migrations/023_byok_key_epochs.sql`
- `backend/internal/byok/epochs.go`
- `backend/cmd/audit-byok-epochs`
- BYOK envelope fields `org_id` и `provider_kid`
- `BYOK_EPOCHS_REQUIRED`
- bundle manifest fields `encrypted_fields` и `key_epochs`
- build gate для `audit-byok-epochs`

# Definition of Done

- New writes используют active epoch по `org_id`, если epoch присутствует.
- `BYOK_EPOCHS_REQUIRED=true` делает отсутствие active epoch fail-closed.
- Reads/decrypt выбирают epoch по `kid`, а provider decrypt получает исходный `provider_kid`.
- Retired epochs читаются, revoked/disabled не используются для decrypt/new writes.
- Cross-tenant envelope rejected.
- Legacy BYOK2 envelopes без epoch metadata продолжают decrypt через inner encryptor.
- Evidence bundle manifest содержит encrypted field/key epoch summary без secrets.
- CLI `audit-byok-epochs` даёт operator-visible create/list/activate/retire/revoke/disable.

# Проверка

Целевые проверки:

- `go test ./internal/byok ./internal/evidencebundle ./cmd/audit-byok-epochs ./cmd/audit-export-evidence ./internal/config -count=1`
- `go test ./internal/audit ./cmd/audit-byok-sweep ./cmd/shadowai -count=1`
- `go test -tags enterprise ./internal/byok ./internal/audit ./cmd/audit-byok-epochs ./cmd/shadowai -count=1`

Финальные full-suite проверки фиксируются в итоговом ответе.

# Риски / зависимости

- В рабочем дереве были pre-existing dirty files; они не должны попасть в коммит.
- `backend/cmd/shadowai/main.go` был dirty до начала работы, но релевантен для BYOK wiring. Изменение ограничено вызовом `configureAuditBYOK(..., db)`.
- BYOK3 v1 не реализует AWS/GCP/Azure/HSM backends.

# Roadmap

v1: tenant DEK epochs для audit payload encryption.

v2+:

- broader payload classes;
- provider-specific customer KMS policies;
- decrypt-on-demand auditor flow;
- searchable/tokenized encryption;
- optional ciphertext Merkle proof RFC.

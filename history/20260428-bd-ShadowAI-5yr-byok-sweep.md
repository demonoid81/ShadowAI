# bd-ShadowAI-5yr — BYOK2.1 legacy audit payload sweep

## Контекст

BYOK2 v1 шифрует `audit_logs.request_body` и `audit_logs.response_body` только для новых writes. Legacy строки до включения BYOK остаются plaintext. Это residual confidentiality gap, зафиксированный в production-hardening и BYOK RFC.

CASS недоступен: `cass health` вернул `index stale`. Источники истины: фактический код, bd-задача `ShadowAI-5yr`, docs после BYOK2.

## Размышления

Рассмотрены варианты:

- Автоматический runtime scheduler re-encrypt.
- DB migration, переписывающая payload без KMS-aware app logic.
- Явный operator CLI с dry-run и batch limit.

Принято решение: operator CLI. Sweep меняет исторические audit payload поля, поэтому он должен запускаться явно, с dry-run и понятным exit code. Автоматический scheduler отклонён: скрытая миграция payload данных усложняет forensic объяснение и rollback.

## План реализации

1. Добавить pure classification tests: plaintext vs empty vs valid envelope vs invalid prefix.
2. Реализовать repository-level batch sweep.
3. Добавить CLI `audit-byok-sweep`.
4. Встроить CLI в Dockerfile, Makefile, CI build loop.
5. Обновить docs и examples.
6. Прогнать targeted/full tests и commit.

## Roadmap

### v1

- Batch re-encrypt legacy audit payload fields.
- Dry-run.
- Idempotent skip valid envelopes.

### v2+

- Per-tenant DEK epochs.
- Audit/admin-event evidence for sweep runs.
- Legal-hold selector encryption.
- Bundle metadata `encrypted_fields`.

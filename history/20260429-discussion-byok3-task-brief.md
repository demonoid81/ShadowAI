# Тема

BYOK3 — DEK epochs / broader key lifecycle.

# Контекст

Источник: `docs/2026-04-17-enterprise-readiness-roadmap.md` и `docs/rfcs/2026-04-pr-byok1-kms-byok-design.md`.

Roadmap указывает BYOK3 как следующий recommended product/security track после закрытых BYOK2 и BYOK2.1. BYOK2/BYOK2.1 закрыли Vault Transit encryption для `audit_logs.request_body` и `audit_logs.response_body`, а также legacy sweep для старых plaintext rows. Оставшийся gap: DEK epochs, tenant/key lifecycle metadata, broader payload classes и customer-specific KMS policies.

# Задача в рабочем формате

## КОНТЕКСТ

ShadowAI уже имеет:

- WORM evidence chain: HMAC row chain, Merkle anchors, Ed25519 signed manifests, evidence bundles.
- Tenant isolation: `org_id` во runtime, audit, governance, purge/export и tenant Merkle subset proofs.
- BYOK2: KMS-backed encryption для новых audit payload writes через Vault Transit.
- BYOK2.1: operator sweep для legacy plaintext audit payload rows.
- W7: keyring/epoch model для integrity/signing keys.

BYOK3 должен перевести BYOK из уровня "поля шифруются" в уровень "ключевой lifecycle управляем и проверяем": epochs, rotation, status, tenant metadata, auditability и forward-compatible tooling.

## ТЕКУЩЕЕ СОСТОЯНИЕ

Сейчас закрыт минимальный encryption path:

- payload шифруется через Vault Transit;
- legacy rows можно прогнать sweep-утилитой;
- WORM verification не зависит от KMS;
- BYOK RFC уже зафиксировал encrypt-after-canonical invariant.

Ограничения текущего состояния:

- нет first-class таблицы/модели DEK epochs;
- нет tenant-level key lifecycle state;
- нет явного статуса ключа: active/retiring/revoked/disabled;
- нет audit trail для key rotation/revoke;
- нет bundle metadata, показывающей какие encrypted fields и key epochs присутствуют;
- нет decrypt-on-demand flow для tenant auditor/operator;
- payload classes кроме `audit_logs.request_body/response_body` остаются v2+.

## ЗАДАЧА

Реализовать BYOK3 v1: tenant-scoped DEK epoch lifecycle для audit payload encryption.

Минимальный v1 scope:

- добавить persistent metadata для per-tenant DEK epochs;
- связать encrypted audit payload envelope с `org_id`, `kid`, `epoch`, `status`;
- добавить rotation flow: create new epoch → mark active → new writes use new epoch;
- обеспечить backward-compatible reads/decrypt для старых epochs;
- добавить admin/audit trail для key lifecycle операций;
- добавить bundle metadata по encrypted fields и key epochs;
- добавить CLI/API для operator-visible key state.

## ТРЕБОВАНИЯ

- Не ломать WORM invariant: chain canonical и row_hash не зависят от ciphertext и KMS.
- Не требовать KMS для `audit-verify --bundle`.
- Все key lifecycle операции tenant-scoped; global_admin может управлять metadata, но payload decrypt требует tenant-authorized KMS.
- Rotation не должна требовать downtime.
- Mixed epochs допустимы: старые rows остаются на старом `kid`, новые writes используют active epoch.
- Revoked/disabled epoch не должен использоваться для новых writes.
- Existing BYOK2 encrypted rows должны читаться после миграции.
- Plaintext legacy support сохраняется только если BYOK2.1 sweep ещё не применён; enforce-mode должен уметь fail-closed.
- Все privileged lifecycle actions пишутся в `admin_event_logs` и SIEM.
- Production validation должен ловить небезопасную конфигурацию: BYOK enabled, но нет active epoch для tenant.

## КРИТЕРИИ ГОТОВНОСТИ

- Есть migration для `byok_key_epochs` или эквивалентной таблицы:
  - `id`, `org_id`, `kid`, `provider`, `status`, `created_at`, `activated_at`, `retired_at`, `revoked_at`, `created_by`, `metadata_json`.
- New audit payload writes выбирают active epoch по `org_id` и пишут envelope с `kid`.
- Reads/decrypt выбирают epoch по `kid`, а не по "текущему активному" ключу.
- Rotation command/API создаёт новый active epoch без переписывания старых rows.
- Retire/revoke command/API меняет статус и блокирует new writes при unsafe state.
- Admin events содержат `source_org_id`, `target_org_id`, actor, action, old/new status.
- Evidence bundle manifest содержит `encrypted_fields` и `key_epochs` summary без plaintext secrets.
- `audit-verify --bundle` продолжает проходить без KMS.
- Тесты покрывают:
  - new write на active epoch;
  - decrypt old row после rotation;
  - no active epoch → fail-closed в BYOK enforce mode;
  - revoked epoch не используется для new writes;
  - unknown `kid` на read → controlled error;
  - bundle manifest включает epochs summary;
  - cross-tenant `kid` нельзя использовать для чужого org.
- Enterprise тесты проходят: `go test -tags enterprise ./...`.
- Если есть CLI, `make build-cli` проходит.

## ДОПОЛНИТЕЛЬНО

Anti-fantasy / edge cases:

- Не обещать HSM/AWS KMS/GCP/Azure integration в BYOK3 v1, если реализация остаётся на Vault Transit.
- Не включать payload ciphertext в WORM canonical без отдельного RFC: это меняет evidence semantics.
- Не делать global "current key" без `org_id`: это ломает tenant BYOK.
- Не удалять старые epochs сразу после rotation: старые rows должны оставаться decryptable.
- Не считать key revoke равным DSAR erasure без отдельной legal/compliance decision.
- Не выводить raw KMS material, wrapped DEK или Vault tokens в bundle/report/logs.
- Не делать silent fallback на plaintext при BYOK enforce mode.

# Размышления

Рассмотрены два варианта: реализовать полный KMS lifecycle сразу или ограничить BYOK3 v1 tenant-scoped epoch metadata и rotation semantics.

Принято решение рекомендовать второй вариант. Он закрывает главный product/security gap без расширения blast radius на HSM, multi-provider KMS и searchable encryption.

Альтернатива "добавить все KMS providers сразу" отклонена как преждевременная: BYOK RFC прямо говорит, что provider-specific требования должны появляться после customer requirements.

Альтернатива "ре-encrypt все старые rows при каждой rotation" отклонена для v1: она тяжёлая, может конфликтовать с evidence/export окнами и не нужна для корректной epoch semantics.

# Варианты

## Вариант A — BYOK3 v1: epoch metadata + rotation semantics

Плюсы:

- Быстро закрывает lifecycle gap.
- Совместим с BYOK2/BYOK2.1.
- Не меняет WORM verification.

Минусы:

- Не даёт multi-KMS abstraction.
- Не решает searchable encryption.

## Вариант B — Full BYOK platform

Плюсы:

- Сильнее для крупных regulated customers.
- Можно сразу включить AWS/GCP/Azure/HSM abstraction.

Минусы:

- Существенно больше scope.
- Высокий риск затянуть задачу и сломать стабильный evidence path.

# Рекомендация

Брать **Вариант A** как BYOK3 v1.

Следующая implementation-задача должна быть не RFC, а кодовая задача с коротким design note внутри history: BYOK1 RFC уже задаёт invariant, а roadmap уже подтверждает направление.

# Открытые вопросы

- Какой точный статусный словарь принять: `pending`, `active`, `retiring`, `retired`, `revoked`, `disabled`.
- Нужен ли endpoint/API для tenant admin или только global_admin/operator CLI.
- Включать ли `admin_event_logs` payload encryption в BYOK3 v1 или оставить как BYOK4.
- Должен ли production validation требовать active epoch для каждого org или только для org с BYOK enabled.

# Возможные следующие шаги

1. Перейти в IMPLEMENTATION по явной команде пользователя.
2. Создать bd-задачу `BYOK3 — tenant DEK epochs`.
3. Проверить текущие BYOK2 файлы и миграции через ast-index/поиск кода.
4. Начать TDD: тесты для epoch selection, rotation и fail-closed behavior.

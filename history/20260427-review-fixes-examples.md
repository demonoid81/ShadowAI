# Примеры для исправления ошибок после ревью

## Happy path 1: restore drill с single signing key

Вход:

```bash
export DATABASE_URL=postgres://user:pass@restore/shadowai
export AUDIT_CHAIN_SECRET=...
audit-verify --restore-drill --table all --pubkey-file ./anchor-pubkey.b64 --verbose
```

Ожидание:

- chain verification выполняется для всех четырёх таблиц;
- anchors проверяются;
- signatures проверяются через single public key;
- exit code `0`, если нарушений нет.

## Happy path 2: restore drill с keyrings

Вход:

```bash
audit-verify \
  --restore-drill \
  --table all \
  --chain-keyring ./chain-keyring.json \
  --signing-keyring ./signing-keyring.json \
  --verbose
```

Ожидание:

- каждая строка chain проверяется секретом своей epoch;
- каждый anchor проверяется публичным ключом своего `pubkey_id`;
- старые и новые epoch поддерживаются в одной команде.

## Edge case 1: evidence collection CronJob при readOnlyRootFilesystem

Вход:

- `readOnlyRootFilesystem: true`;
- mounted `emptyDir` в `/staging`;
- `audit-collect-evidence` создаёт временные файлы.

Ожидание:

- `TMPDIR=/staging/tmp`;
- временные файлы создаются внутри writable mount;
- запись в `/tmp` не требуется.

## Edge case 2: W8 additional file sink

Вход:

- anchor записан в primary DB;
- `audit_chain_anchor_sinks` содержит `sink_name=file://` и `sink_ref=file:///.../anchors.ndjson`;
- файл содержит signed manifest с тем же table/range/root/signature.

Ожидание:

- `audit-verify --include-anchors` выводит additional sink result;
- mismatch root или отсутствующая запись дают verification failure.

## Edge case 3: single public key и anchor с pubkey_id

Вход:

```bash
audit-verify --verify-sink --pubkey-file ./anchor-pubkey.b64 ...
```

Anchor уже содержит `pubkey_id`, но оператор передаёт один публичный ключ вместо keyring.

Ожидание:

- single-key compatibility mode проверяет подпись этим ключом;
- наличие `pubkey_id` не приводит к false negative;
- multi-keyring mode по-прежнему fail-closed при неизвестном `pubkey_id`.

## Failure case: restore drill без signing key

Вход:

```bash
export DATABASE_URL=postgres://user:pass@restore/shadowai
export AUDIT_CHAIN_SECRET=...
audit-verify --restore-drill --table all --verbose
```

Ожидание:

- команда завершается с exit code `2`;
- ошибка указывает, что нужен `--pubkey`, `--pubkey-file` или `--signing-keyring`;
- signature tier не пропускается silently.

# Исправление ошибок после полного ревью проекта

## Контекст

Полное ревью проекта выявило несколько production/compliance дефектов в путях evidence collection, WORM verification и Helm CronJob.

CASS проверен командой `cass health`, но недоступен из-за stale index. bd проверен командой `bd ready --json`, однако создание задачи невозможно: локальная база не инициализирована (`issue_prefix` отсутствует). По контракту проекта `bd init` не выполняется агентом, поэтому факты фиксируются в history, а источником истины остаются код, Helm-шаблоны и документация.

## Цель

Исправить найденные ошибки без отката существующих пользовательских изменений и без расширения scope за пределы review findings.

## Размышления

Рассмотрены варианты:

- Оставить `audit-verify --restore-drill` совместимым со старым поведением и пропускать signature tier без публичного ключа. Альтернатива отклонена: команда заявляет full restore drill, поэтому silent skip подписи создаёт ложное чувство верификации.
- Сделать signing key обязательным только для ручного `--verify-signatures`, но не для `--restore-drill`. Альтернатива отклонена: restore drill должен включать chain, anchors и signatures как единый high-confidence путь.
- Проверять W8 additional sinks только отдельным новым флагом. Альтернатива отклонена: `--include-anchors`, `--anchor-only` и `--verify-sink` уже являются операторскими проверками evidence posture; recorded additional sinks должны попадать в эти результаты.
- Использовать `/tmp` в evidence collection CronJob. Альтернатива отклонена: контейнер работает с `readOnlyRootFilesystem`, поэтому writable temp должен быть внутри явного `emptyDir` mount.

Принято решение:

- `audit-collect-evidence` запускает chain verify только при наличии DB, chain key и signing key.
- `audit-verify --restore-drill` fail-fast требует `--pubkey`, `--pubkey-file` или `--signing-keyring`.
- Все четыре WORM таблицы используют keyring-aware verification при `--chain-keyring`.
- W8 additional sinks проверяются через recorded `audit_chain_anchor_sinks`, включая `file://` и `immudb://`.
- W8 sink verification использует W7 signing keyring, если он передан; single-key режим остаётся совместимым с anchors, у которых уже есть `pubkey_id`.
- Evidence collection CronJob направляет `TMPDIR` в `/staging/tmp`.

## Scope In

- Helm evidence collection CronJob.
- `audit-collect-evidence` restore-drill preconditions.
- `audit-verify` restore-drill/signature/keyring behavior.
- WORM chain verifier для `admin_event_logs`, `legal_hold_events`, `audit_purge_runs`.
- W8 additional sink verification.
- Single-key signing keyring compatibility для sink/signature verification.
- Regression tests for file sink manifest matching.
- Документация restore-drill.

## Scope Out

- Новые product features.
- Изменение tenant isolation, org budget или SOC2 flows.
- Инициализация bd базы.
- Откат существующих пользовательских изменений в рабочем дереве.

## План реализации

1. Проверить затронутые CLI, Helm и chain verifier paths.
2. Исправить Helm tempdir и передачу optional `anchorPubKey`.
3. Обновить `audit-collect-evidence` preconditions и аргументы subprocess.
4. Добавить keyring-aware verification для оставшихся WORM таблиц.
5. Добавить verification path для W8 additional sinks.
6. Обновить документацию и history.
7. Запустить targeted/full verification.

## Definition of Done

- `go test ./internal/chain ./cmd/audit-verify ./cmd/audit-collect-evidence -count=1` проходит.
- `go test ./... -count=1` проходит или failure зафиксирован.
- `go test -tags enterprise ./... -count=1` проходит или failure зафиксирован.
- `make build-cli` проходит.
- `make helm-validate` проходит.
- `git diff --check` проходит.
- History plan/examples созданы.
- Изменения подготовлены к отдельному коммиту без unrelated user files.

## Риски и зависимости

- В рабочем дереве есть существующие изменения пользователя. Они не откатываются и не включаются в scope без необходимости.
- bd недоступен, поэтому формальный `bd close` невозможен.
- CASS index stale, поэтому прошлый контекст не используется как источник истины.

## Roadmap

### v1

Закрыть review findings и восстановить соответствие между кодом, Helm и документацией.

### v2+

Добавить отдельные integration-тесты для W8 multi-sink verification с реальной БД и recorded `audit_chain_anchor_sinks`.

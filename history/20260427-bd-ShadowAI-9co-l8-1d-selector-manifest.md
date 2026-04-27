# bd-ShadowAI-9co — PR-L8.1d selector manifest для evidence bundle

## Контекст

L8.1b/L8.1c включили runtime-путь для `query_scope` legal holds:
создание, WORM canonical v2 и purge enforcement. Остался auditor-facing gap:
portable evidence bundle содержал anchors, chain inventory / tenant Merkle
proofs, но не раскрывал selector details, необходимые для объяснения того,
какой набор audit rows должен был сохраняться.

Фактические источники:

- `docs/rfcs/2026-04-pr-l8-legal-hold-query-scope-rfc.md` D11 требует
  selector manifest lines в evidence bundle.
- `history/20260427-discussion-next-task-l8-1d-selector-manifest.md`
  рекомендует PR-L8.1d как следующий шаг.
- `docs/production-hardening.md` до этой задачи фиксировал selector manifest
  как остаточный gap.

## Цель

Добавить `selector_manifest.jsonl` в global и tenant evidence bundles и
расширить offline verification так, чтобы auditor мог проверить:

```text
SHA256(normalized selector_json) == selector_hash
```

без доступа к live DB и без `AUDIT_CHAIN_SECRET`.

## Scope

In:

- `selector_manifest.jsonl` с `hold_id`, `org_id`, `scope_type`,
  `selector_hash`, `selector_version`, `selector_json`.
- Global export включает все `query_scope` selectors.
- Tenant export включает только selectors текущего `org_id`.
- `bundle_manifest.json.file_sha256` включает новый файл.
- `audit-verify --bundle` проверяет selector manifest для global и tenant
  bundles.
- Старые bundles без `selector_manifest.jsonl` остаются backward-compatible.

Out:

- Hash-only selector export flag.
- BYOK/KMS encryption для selector JSON.
- Runtime purge logic.
- Admin/SIEM metadata changes.

## План реализации

1. Добавить red-тесты для global verifier, tenant verifier и DB fetcher.
2. Ввести `SelectorManifestLine`, repository fetcher и verifier helper.
3. Подключить verifier в `VerifyBundle` и `VerifyTenantBundle`.
4. Подключить `audit-export-evidence` к fetch/write selector manifest.
5. Обновить CLI output, README bundle text и production-hardening gap.
6. Прогнать targeted и enterprise regression.

## Размышления

Рассмотрены варианты: сделать selector manifest обязательным для всех bundle
versions или оставить backward-compatible отсутствие файла.

Принято решение сохранить backward compatibility: новые exports всегда пишут
`selector_manifest.jsonl`, но старые bundles без файла проходят offline verify
с `Missing=true`. Это не ослабляет новые compliance artifacts, но не ломает
архивные bundles.

Рассмотрены варианты: проверять только `selector_hash` как строку или
перекомпилировать selector через production compiler.

Принято решение использовать `legalholdselector.Compile`: это гарантирует тот
же normalized JSON/hash contract, что и runtime create/preview path.

Альтернатива hash-only v1 отклонена: RFC D11 требует default compliance
bundle с selector JSON для auditor explainability. Hash-only остаётся v2+.

## Definition of Done

- Bundle содержит `selector_manifest.jsonl`, даже если `query_scope` holds
  отсутствуют.
- Tampered selector JSON ломает `audit-verify --bundle`.
- Tenant export не раскрывает cross-tenant selectors.
- Global export содержит все `query_scope` selectors.
- Новый файл включён в `bundle_manifest.json.file_sha256`.
- Docs фиксируют оставшийся privacy tradeoff: selector JSON экспортируется,
  hash-only/BYOK mode ещё не реализован.

## Проверка

- `go test ./internal/evidencebundle -count=1`
- `go test ./internal/evidencebundle ./cmd/audit-export-evidence ./cmd/audit-verify -count=1`
- `go test -tags enterprise ./... -count=1`
- `git diff --check`

## Риски / зависимости

- Selector JSON раскрывает расследовательскую стратегию; mitigated через
  tenant-scoped export. Hash-only/BYOK selector bundle mode остаётся v2+.
- `legal_holds` enterprise-only table: exporter предполагает enterprise DB
  для legal hold evidence bundle.
- Existing archived bundles без selector manifest не получают новый signal,
  но остаются верифицируемыми по старым проверкам.

## Roadmap

v1:

- `selector_manifest.jsonl` + offline hash verification.

v2+:

- `--selector-manifest=full|hash-only`.
- BYOK/KMS encryption selector JSON.
- Auditor UI/report для selector manifest summary.

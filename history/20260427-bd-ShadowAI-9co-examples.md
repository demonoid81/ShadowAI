# bd-ShadowAI-9co — примеры L8.1d selector manifest

## Happy path 1 — global bundle

В БД есть два `query_scope` legal holds:

- `hold-a`, `org-a`, selector `provider == openai`;
- `hold-b`, `org-b`, selector `provider == anthropic`.

Оператор запускает:

```bash
audit-export-evidence --global --output /exports/global-2026q2
```

Ожидаемо:

- `selector_manifest.jsonl` содержит обе строки;
- `bundle_manifest.json.file_sha256` содержит hash для
  `selector_manifest.jsonl`;
- `audit-verify --bundle /exports/global-2026q2` проверяет оба selector hash.

## Happy path 2 — tenant bundle

В БД есть `query_scope` holds для `org-a` и `org-b`.

Оператор запускает:

```bash
audit-export-evidence --org-id org-a --output /exports/org-a-2026q2
```

Ожидаемо:

- `selector_manifest.jsonl` содержит только selectors `org-a`;
- selectors `org-b` не экспортируются;
- tenant verifier проверяет selector manifest вместе с Merkle proofs.

## Edge case 1 — нет query_scope holds

В БД нет legal holds со `scope_type='query_scope'`.

Ожидаемо:

- exporter всё равно пишет пустой `selector_manifest.jsonl`;
- файл включён в `bundle_manifest.json.file_sha256`;
- `audit-verify --bundle` возвращает `checked=0`, `OK=true`.

## Edge case 2 — старый bundle без selector_manifest.jsonl

Auditor проверяет bundle, созданный до L8.1d.

Ожидаемо:

- `audit-verify --bundle` не падает из-за отсутствия файла;
- результат selector check: `Missing=true`, `OK=true`;
- остальные checks работают по старому контракту.

## Failure — selector_json изменён после export

Злоумышленник меняет строку:

```json
{"v":1,"field":"provider","op":"eq","value":"openai"}
```

на:

```json
{"v":1,"field":"provider","op":"eq","value":"anthropic"}
```

и пересчитывает `bundle_manifest.json.file_sha256`, чтобы обычная file
integrity проверка прошла.

Ожидаемо:

- `audit-verify --bundle` перекомпилирует `selector_json`;
- computed selector hash отличается от stored `selector_hash`;
- selector check возвращает `FAIL`;
- общий bundle result возвращает exit 1.

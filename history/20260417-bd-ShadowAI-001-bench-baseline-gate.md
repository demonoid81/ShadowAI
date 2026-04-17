# bd-ShadowAI-001: PR-6.1.1 — закрытие fail-open gap для semantic_v2 baseline

**Дата:** 2026-04-17
**Статус:** реализовано.

## Контекст

PR-6.1 интегрировал `semantic_v2` в benchmark harness, но оставил
fail-open gap: если baseline не содержит запись для `semantic_v2`,
`runSemanticV2` писал warning и возвращал `exitOK`. README уже
требовал metadata-locked baseline, но runtime не enforcил это.

Итог: CI slot `--with-embeddings` мог "успешно пройти" без реального
regression gate, если оператор забыл добавить `semantic_v2` entry
(или добавил без полного metadata lock). Это ломает сам смысл PR-5/6.1:
committed baseline — единственное, что делает benchmark regression-
chувствительным.

## Контракт (финальный)

| Случай                                                            | exit | Снимается `--allow-missing-baseline` |
|-------------------------------------------------------------------|------|--------------------------------------|
| Полноценный `semantic_v2` entry + metadata lock + thresholds      | 0/2¹ | —                                    |
| Baseline не содержит `semantic_v2`                                | 1    | ✓ (→ 0 + warning)                    |
| Entry есть, но `provider`/`model`/`corpus_version` отсутствуют    | 1    | ✓ (→ 0 + warning)                    |
| Metadata mismatch runtime vs baseline                             | 1    | ✗ (misconfig, не bootstrap)          |
| Corrupt / invalid JSON в baseline                                 | 1    | ✗ (PR-5.1 contract)                  |
| Baseline file не существует                                       | 1    | ✓ (PR-5.1 contract)                  |

¹ — `exit 2` при regression, `exit 0` при pass thresholds.

Граница выстроена вокруг bootstrap semantics:
- "missing/incomplete" = "я ещё не дошёл до создания baseline entry" →
  снимается флагом;
- "mismatch / corrupt" = "что-то сломано" → никогда не снимается.

## Реализация

### `runSemanticV2` (main.go)

Новая полнота-проверка baseline перед metadata-match и Run:

```go
hasEntry := baseline.HasInspector("semantic_v2")
bp, bm, bcv := baseline.MetadataFor("semantic_v2")
baselineReady := hasEntry && bp != "" && bm != "" && bcv > 0

if !baselineReady {
    if !allowMissingBaseline {
        // Разные сообщения для missing entry vs incomplete metadata
        return exitRuntime
    }
    // allowMissing: warning, прогоняем без regression-check
}
```

- `CheckInspectorMetadata` вызывается **только** при `baselineReady`
  (иначе сравнивать нечего).
- `CheckRegression` применяется **только** при `baselineReady`.
  В bootstrap-пути результат попадает в `report.Results`, но
  regression-count не растёт.

Параметр `allowMissingBaseline` прокинут из `run()` → `runSemanticV2()`.

### Тесты

3 новых (`with_embeddings_test.go`):

1. `TestRun_WithEmbeddings_MissingSemanticV2Baseline_FailsHard` —
   baseline без `semantic_v2` entry → exit 1, stderr упоминает
   `semantic_v2` и `--allow-missing-baseline`.
2. `TestRun_WithEmbeddings_IncompleteSemanticV2Metadata_FailsHard` —
   entry есть, но `provider=""` → exit 1, stderr упоминает
   "incomplete metadata lock".
3. `TestRun_WithEmbeddings_MissingSemanticV2Baseline_WithAllowFlag` —
   тот же сетап + `--allow-missing-baseline` → exit 0, result
   попадает в report, warning с "allow-missing-baseline" в тексте.

Фикстуры: два новых `writeBaselineWithoutSemanticV2` и
`writeBaselineWithIncompleteSemanticV2` в том же файле.

### Docs (`testdata/firewall_bench/README.md`)

Раздел "semantic_v2 (`--with-embeddings`)" расширен явной таблицей
поведения:
- три случая missing/incomplete/mismatch;
- какой exit code;
- что снимается `--allow-missing-baseline`, а что нет.

## Размышления

- Рассмотрено: разделить `--allow-missing-baseline` на два флага
  (`--allow-missing-file` и `--allow-missing-entry`). Отклонено —
  оба случая про bootstrap, один флаг читабельнее в docs.
- Рассмотрено: в allowMissing-path пропускать и Run (только
  warning без метрик). Отклонено — оператору в bootstrap полезно
  видеть P/R/FPR mock-прогона, чтобы уже иметь отправную точку
  при заполнении baseline.
- Рассмотрено: принять `corpus_version == 0` как валидный "не задано".
  Отклонено — JSON-default для `int` тоже 0, такое поведение
  неотличимо от "забыли проставить"; лучше требовать явно > 0.

## Definition of Done

- [x] `runSemanticV2` принимает `allowMissingBaseline` и проверяет
      полноту baseline-entry перед metadata-match.
- [x] 3 новых теста, все существующие bench-тесты проходят без
      изменений.
- [x] README обновлён с явной таблицей поведения.
- [x] `go test ./...` зелёный.

## Что дальше (по согласованному плану ревью)

1. Реальный прогон `--with-embeddings` на Ollama + nomic-embed-text.
2. Зафиксировать `semantic_v2` entry в `testdata/firewall_bench/baseline.json`
   с полным metadata lock.
3. Посмотреть реальные P/R/FPR.
4. Уже потом решать: PR-7 (Stage 2 streaming passthrough) или
   расширение corpus/datasets.

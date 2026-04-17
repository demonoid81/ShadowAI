# bd-ShadowAI-mom: PR-6.0.1 — corpus normalized=true требование + reproducible GeneratedAt

**Дата:** 2026-04-17
**Статус:** реализовано.

## Контекст

Ревью PR-6 нашло два issue:

1. **Medium.** `LoadCorpus` проверяет unit-length items только при
   `Normalized=true`, но сам флаг не требует. Manifest с `normalized=false`
   (или opuщенным полем — zero-value `false`) проходит валидацию, но
   hot path (`MaxSim`) всё равно делает dot-product, предполагая
   unit-length. Результат — silent wrong similarity, ломающая thresholds.
2. **Low.** `firewall-corpus-gen` пишет `time.Now().UTC()` в
   `GeneratedAt`, что делает output non-deterministic. Если в будущем
   корпус попадёт в репо (sidecar CI с Ollama или reproducible-builds
   pipeline), diff'ы будут шумными даже без реальных изменений.

## Исправления

### LoadCorpus требует `Normalized=true`

```go
if !c.Normalized {
    return nil, fmt.Errorf("corpus: manifest must declare normalized=true (hot path assumes L2-normalized vectors for dot-product cosine)")
}
```

Тест `TestLoadCorpus_RejectsNormalizedFalse`: manifest валиден во всём,
кроме `normalized: false` → LoadCorpus возвращает error. Существующий
`semantic_v2.example.json` уже имеет `normalized: true`, регрессия
в committed артефактах отсутствует. `Generate` всегда пишет `true`.

### SOURCE_DATE_EPOCH для reproducible output

```go
func resolveGeneratedAt() time.Time {
    if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
        if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
            return time.Unix(sec, 0).UTC()
        }
    }
    return time.Now().UTC()
}
```

- Env var задан → используем его (UTC).
- Не задан ИЛИ невалиден (мусор в значении) → fallback `time.Now().UTC()`.

Выбрана стандартная конвенция reproducible-builds (Debian / NixOS / Go
release machinery), а не кастомный CLI flag: surface area меньше,
оператор уже знает паттерн.

Два новых теста:
- `TestGenerate_ReproducibleWithSourceDateEpoch` — два прогона с
  фиксированным SOURCE_DATE_EPOCH дают byte-identical output +
  `GeneratedAt.Unix()` равен установленному значению.
- `TestGenerate_InvalidSourceDateEpoch_FallsBackToNow` — мусорный
  env var не ломает Generate, fallback работает.

### Docs

`backend/firewall_corpus/README.md` дополнен:
- пример `SOURCE_DATE_EPOCH` в CI-сценарии;
- заметка под Manifest-секцией, что `normalized=true` — обязательный
  контракт.

## Размышления

- Рассмотрено: `--generated-at` CLI-флаг вдобавок к env var. Отклонено —
  env достаточно выразителен, два override'а на один use-case только
  расширяют API без пользы.
- Рассмотрено: мягкий warning при `normalized=false` вместо fail-fast.
  Отклонено — hot-path математика зависит от инварианта, warning без
  enforce превратится в неуслышанную проблему при ротации корпуса.
- Рассмотрено: добавить тест, что `semantic_v2.example.json`
  проходит `LoadCorpus`. Не добавлен — уже покрывается косвенно тем,
  что любой LoadCorpus тест использует идентичный shape. Явный smoke
  с file I/O добавит шум без новой проверочной силы.

## Definition of Done

- [x] `LoadCorpus` fail-fast при `normalized != true`.
- [x] `firewall-corpus-gen` поддерживает SOURCE_DATE_EPOCH с fallback
      на time.Now().
- [x] Три новых теста (1 corpus + 2 generator).
- [x] Docs обновлены (SOURCE_DATE_EPOCH пример + normalized=true
      контракт).
- [x] `go test ./...` зелёный.

## Дальше

План, согласованный в ревью:
1. ✅ PR-6.0.1 — этот PR.
2. **PR-6.1** — интеграция `semantic_v2` в `firewall-bench`
   (опциональный `--with-embeddings` slot + baseline-блок с
   embedding thresholds).
3. Решение про PR-7 (Stage 2 streaming) — только после benchmark-
   сигналов из PR-6.1.

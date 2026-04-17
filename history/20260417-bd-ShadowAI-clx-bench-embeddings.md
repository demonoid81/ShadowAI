# bd-ShadowAI-clx: PR-6.1 — semantic_v2 в firewall-bench

**Дата:** 2026-04-17
**Статус:** реализовано.

## Контекст

PR-6 добавил embedding-based inspector, но benchmark harness (`cmd/firewall-bench`)
его не знал. Цепочка "измерение → baseline → regression-gate" работала
только для heuristic-инспекторов (`prompt_injection`, `jailbreak`).
Без интеграции PR-6 невозможно было подтвердить, закрывает ли
embedding-слой detection gap, показанный PR-5.

## Контракт (после ревью)

| Требование                                                    | Решение                                                 |
|---------------------------------------------------------------|---------------------------------------------------------|
| `semantic_v2` НЕ в обычном `--all` по умолчанию               | Отдельный flag `--with-embeddings`                       |
| Offline CI не зависит от embedding сервиса                    | Без флага — текущее heuristic-поведение, никаких deps    |
| Baseline тесно привязан к provider/model/corpus_version       | Новые опциональные поля `Provider/Model/CorpusVersion`   |
| Metadata mismatch — misconfig, не regression                  | Exit 1 + diff в stderr до Run                            |
| Отдельный CI-slot для embeddings                              | README: sample YAML с Ollama sidecar-контейнером         |

## Реализация

### `internal/firewallbench/baseline.go`

- `InspectorBaseline` расширен:
  ```go
  Provider      string `json:"provider,omitempty"`
  Model         string `json:"model,omitempty"`
  CorpusVersion int    `json:"corpus_version,omitempty"`
  ```
  Поля опциональные — для heuristic-инспекторов в baseline их нет,
  для embedding-based обязательны.
- `Baseline.CheckInspectorMetadata(name, provider, model, corpusVersion)`
  → `[]Regression` с Field'ами `provider|model|corpus_version`.
- `Baseline.MetadataFor(name)` — возвращает записанные metadata
  (для форматирования error-сообщений).
- 8 тестов в `baseline_metadata_test.go`: match, каждый тип
  mismatch по отдельности, multiple mismatches, no metadata →
  no errors, unknown inspector → no errors, metadata getter.

### `cmd/firewall-bench`

- Новый флаг `--with-embeddings` (default false). Без него прогон
  ведёт себя ровно как до PR-6.1 (регрессионный guard).
- `buildSemanticV2FromEnv()` читает тот же набор env-vars, что и
  `cmd/shadowai/main.go` — единый контракт конфигурации.
- `runSemanticV2()` — отдельный pass:
  - init error → exit 1;
  - metadata mismatch vs baseline → exit 1 с printed diff
    `baseline: provider=... model=... cv=...`
    `runtime:  provider=... model=... cv=...`;
  - dataset load — объединение positive/negative из всех категорий
    (corpus mixed-categorial, разделение по категориям не имеет смысла);
  - `baseline.CheckRegression` добавляется в общий `report.Regressions`
    → поднимает exit до 2 при нарушении порогов.
- Поддержка `--with-embeddings` без `--all`/`--inspector`: валидный
  режим "прогоним только semantic_v2".

### Тесты (`with_embeddings_test.go`)

5 tests, используют `httptest.Server` как mock Ollama:
- `TestRun_WithEmbeddings_HappyPath` — CLI доходит до
  `report.Results[].inspector == "semantic_v2"` с non-zero recall.
- `TestRun_WithEmbeddings_MetadataMismatch` — baseline zafixирован на
  `openai`, runtime `ollama` → exit 1 + diagnostic в stderr.
- `TestRun_WithoutFlag_SemanticV2Skipped` — `--all` без
  `--with-embeddings` не прогоняет semantic_v2 (guard для offline CI).
- `TestRun_WithEmbeddingsAlone` — только `--with-embeddings` (без
  `--all`/`--inspector`) — валидный прогон.
- `TestRun_WithEmbeddings_MissingCorpus_FailsInit` — corpus файл
  не существует → exit 1 (не regression).

Mock-Ollama использует keyword-based embedding (`[1,0]` для
threat-words, `[0,1]` иначе). Для baseline thresholds тестам
намеренно использованы слабые значения (0.5/0.5/0.5) — это wiring
test, а не качество детектора. Real-world метрики придут из PR-6.x
с реальной моделью.

### Docs (`testdata/firewall_bench/README.md`)

- Полный env-var контракт для `--with-embeddings`.
- Пример baseline-записи с metadata lock.
- Sample CI-workflow с двумя job'ами:
  - `firewall-bench-offline` — blocking, fast, без deps;
  - `firewall-bench-embeddings` — optional, с Ollama sidecar.

## Размышления

- Рассмотрено: сделать `semantic_v2` встроенным в `Registry()`
  вместе с heuristic, с automatic-skip если client/corpus недоступен.
  Отклонено — "automatic skip" превращается в silent degradation:
  CI зелёный, detection слой выключен. Явный флаг делает зависимость
  видимой.
- Рассмотрено: отдельный manifest file для embedding-baseline.
  Отклонено — один baseline.json с per-inspector секциями проще,
  metadata lock через opcional поля добавляется без форматного shift'а.
- Рассмотрено: запускать semantic_v2 per-category (отдельные метрики
  для prompt_injection vs jailbreak). Отклонено для MVP — corpus
  mixed-categorial, метрики одного "общего" detector'а легче
  интерпретируются. Per-category split — v2 roadmap.

## Definition of Done

- [x] `InspectorBaseline` + `CheckInspectorMetadata`/`MetadataFor` +
      8 тестов.
- [x] `--with-embeddings` flag + semanticV2Setup + runSemanticV2.
- [x] 5 integration-тестов с mocked Ollama.
- [x] README обновлён: env, baseline schema, CI patterns.
- [x] `go test ./...` зелёный; heuristic regression — поведение PR-5/5.1
      не затронуто.

## Дальше

PR-5 benchmark показывает detection gap, теперь есть инструмент, чтобы
измерить embedding-эффект:

1. Оператор/CI разворачивает Ollama, генерирует corpus через
   `cmd/firewall-corpus-gen`, прогоняет `--with-embeddings` в
   staging/pipeline.
2. Реальные метрики semantic_v2 (provider=ollama, model=nomic-embed-text)
   фиксируются в baseline с metadata lock.
3. На основании сигналов из benchmark принимается решение о PR-7
   (Stage 2 streaming passthrough) — как сейчас советовал ревьюер:
   "сначала измерить, что semantic_v2 действительно помогает,
   потом уходить в streaming epic".

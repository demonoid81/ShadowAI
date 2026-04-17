# bd-ShadowAI-mj4: PR-6 — Semantic V2 embedding-based inspector

**Дата:** 2026-04-17
**Статус:** реализовано.

## Контекст

PR-5 benchmark показал очевидный detection gap:
- prompt_injection: recall=0.24
- jailbreak: recall=0.025 (heuristic-only, `judge=nil`)

Heuristic regex-patterns не ловят paraphrases и creative атаки. PR-6
вводит второй слой — embedding-based inspector, который сравнивает
cosine similarity запроса с precomputed corpus known-атак. Это
адресует paraphrase-устойчивость (семантика вместо точных токенов).

V2 работает **рядом** с V1 (Jaccard), не замещает его: V1 остаётся
детерминистическим lightweight-слоем, V2 добавляет семантическую
глубину ценой внешней зависимости на embedding provider.

## Контракт (после ревью)

| Требование                                                 | Решение                                                                    |
|------------------------------------------------------------|----------------------------------------------------------------------------|
| Runtime/corpus metadata должны совпадать                   | `NewSemanticV2Inspector` → fail-fast error при provider/model/dim mismatch |
| Startup mismatch blocks inspector (не app)                 | main.go логирует, skip'ает регистрацию, pipeline стартует без V2           |
| Runtime embedding errors — fail-open, но с метриками       | `ActionAllow` + warning log; счётчики в embedding package                  |
| Threshold + BlockThreshold (градация flag/block)           | Отдельные float конфиг-поля, валидация block ≥ threshold                   |
| Corpus pre-normalized → dot-product на hot path            | `l2Normalize` в client'е + `isUnitVector` check при LoadCorpus             |
| Status API безопасный (без endpoint/api-key)               | `SemanticV2Status`: provider/model/dim/thresholds/corpus_stats             |
| Production corpus НЕ коммитится                            | Commit'ится `semantic_v2.example.json` + patterns; `.json` генерит оператор |

## Реализация

### Package `internal/embedding`

- **`client.go`**
  - `Config{Provider, Endpoint, Model, APIKey, Timeout, Dimension}`.
    Валидация в `NewClient` (fail-fast).
  - `Embedder` interface (unit-тесты inspector'а без HTTP-моков).
  - `Embed(ctx, text)` → HTTP → L2-normalize → dimension check против
    `cfg.Dimension`.
  - `IsTimeout(err)` — разделение timeout vs fail metric buckets.
  - 7 HTTP-mock тестов: Ollama/OpenAI shapes, normalization, dim
    mismatch, 5xx, timeout, zero-vector guard, config validation.
- **`corpus.go`**
  - `Corpus{Version, Provider, Model, Dimension, Normalized, Items}`.
  - `LoadCorpus(path)`: валидация shape, dim-per-item, normalization
    actual check (numeric noise tolerance 1e-5).
  - `MaxSim(query)` → dot-product на нормированных векторах (cosine ≡ dot).
  - 9 тестов: happy path, reject unknown version, dim/normalization
    mismatches, empty items, exact/orthogonal/angle60° MaxSim,
    edge cases empty/dim-mismatch → `sim=0, nil`.

### `firewall/semantic_v2.go`

- `SemanticV2Config{Enabled, Threshold, BlockThreshold}`.
- `NewSemanticV2Inspector(cfg, client, corpus)`:
  - `nil`-check client и corpus.
  - **Fail-fast metadata match**: `client.Provider/Model/Dimension()`
    должны совпадать с `corpus.*`.
  - Threshold-валидация только при `Enabled` (pre-configure сценарий).
- `InspectRequest`:
  - Disabled → Allow.
  - Empty text → Allow.
  - `client.Embed` error → Allow + warning log (fail-open).
  - `MaxSim ≥ BlockThreshold` → `ActionBlock` + Critical severity.
  - `MaxSim ≥ Threshold` → `ActionFlag` + Medium severity.
  - Finding содержит similarity, match_id, category (но не plaintext
    corpus entry — это операционная метадата, а не leak).

**10 тестов** `semantic_v2_test.go`:
- init rejects provider/model/dim/block<threshold mismatches (4);
- disabled → Allow (1);
- block/flag/allow по sim-уровню (3);
- fail-open на embed error (1);
- Name() контракт (1).

### `cmd/firewall-corpus-gen`

CLI для оффлайн-генерации manifest:
- `--patterns <dir>` с `<category>.txt` файлами.
- `--output <file>`, `--provider|endpoint|model|dimension|timeout`.
- Deterministic порядок: категории + line-number.
- Atomic write: tmp-файл → rename (не оставляем частичный output при
  ошибке embedding).
- 5 тестов через `fixedEmbedder`: happy path, load-by-LoadCorpus roundtrip,
  abort on embed error (no partial write), skip blank lines, reject empty
  patterns dir.

### `status.go`

- `InspectorStatus.SemanticV2 *SemanticV2Status` — per-inspector info.
- `SemanticV2Status`: Provider, Model, Dimension, Threshold,
  BlockThreshold, CorpusVersion, CorpusItems. **Не содержит** endpoint
  и APIKey.
- 2 теста (`status_semanticv2_test.go`): exposes safe metadata;
  endpoint/APIKey не утекают в output.

### Метрики (`internal/metrics`)

Отдельные counters для embedding layer (не overlap'ятся с firewall
decisions):
- `shadowai_embedding_requests_total{provider, model}`
- `shadowai_embedding_fail_total` (HTTP/parse/build)
- `shadowai_embedding_timeout_total` (deadline exceeded)
- `shadowai_embedding_latency_seconds{provider, model}` (histogram,
  только success, buckets 50ms..10s)

Rationale: если обобщать в `firewall_decisions_total`, деградация
embedding layer (массовые timeout'ы → все Allow) не будет видна в
dashboards — V2 inspector из viewpoint firewall просто "ничего не
находит".

### Config + main.go wire

Env vars (default values позволяют dev-startup без V2):
```
FIREWALL_SA_V2_ENABLED=false           # default off (нужен corpus)
FIREWALL_SA_V2_THRESHOLD=0.75
FIREWALL_SA_V2_BLOCK_THRESHOLD=0.88
FIREWALL_SA_V2_CORPUS_PATH=firewall_corpus/semantic_v2.json
FIREWALL_EMBEDDING_PROVIDER=ollama
FIREWALL_EMBEDDING_ENDPOINT=http://localhost:11434
FIREWALL_EMBEDDING_MODEL=nomic-embed-text
FIREWALL_EMBEDDING_API_KEY=
FIREWALL_EMBEDDING_DIMENSION=768
FIREWALL_EMBEDDING_TIMEOUT=10s
```

В `main.go` при `SA_V2_ENABLED=true`:
1. `embedding.NewClient` — fail → log + skip.
2. `embedding.LoadCorpus` — fail → log + skip.
3. `firewall.NewSemanticV2Inspector` — fail (metadata mismatch) → log + skip.
4. Регистрация + лог: `"semantic_v2: registered (provider=... items=...)"`.

**Pipeline никогда не падает из-за V2 инициализации**: оператор видит
reason в логах и может исправить (неверный corpus, unreachable endpoint,
mismatch provider). Остальные inspectors работают.

### Committed artifacts

`backend/firewall_corpus/`:
- `README.md` — генерация, формат, observability.
- `patterns/prompt_injection.txt` — 30 канонических паттернов (EN+RU).
- `patterns/jailbreak.txt` — 25 паттернов (DAN/STAN/AIM + curated).
- `semantic_v2.example.json` — stub-manifest dim=4, `provider=example`
  (никогда не проходит fail-fast match против реального client'а,
  но демонстрирует shape).

Production manifest `semantic_v2.json` **НЕ коммитится**: он жёстко
привязан к выбранному `{provider, model, dim}`, а один committed файл
превратил бы multi-provider контракт в фикцию. Оператор генерирует
свой при deploy через `firewall-corpus-gen`.

## Размышления

- Рассмотрено: OpenAI как единственный provider для MVP. Отклонено
  (по C/A/A + корректировки): нужно configurable (ollama для dev/CI,
  openai для prod), но с жёстким metadata-lock через corpus. Это и
  сделано.
- Рассмотрено: commit production corpus. Отклонено: provider-lock
  делает один файл бессмысленным для multi-tenant setup.
- Рассмотрено: fail-close вместо fail-open на embedding error. Отклонено:
  embedding provider может быть rate-limit'нут/в downtime, fail-close
  превратит firewall в SPOF. Observability (отдельные counters + warning
  log) достаточны для детекции.
- Рассмотрено: MaxSim через knn (top-k). Отклонено: MVP достаточно max.
  В v2 — top-k с voting (если несколько items одного category
  одновременно близки, доверие выше).
- Рассмотрено: store corpus в binary format (flat float32 array).
  Отклонено: JSON проще для diff/review/version-control; 768-dim *
  float64 * 50 items = ~300KB, vs 100KB для float32 binary — не
  критично для repo size.

## Definition of Done

- [x] `internal/embedding/`: client + corpus + 16 тестов.
- [x] `internal/firewall/semantic_v2.go` + 10 тестов.
- [x] `cmd/firewall-corpus-gen` + 5 тестов.
- [x] `status.go` + 2 теста на safe metadata exposure.
- [x] Embedding metrics: 4 counters + histogram, test в metrics_test.go.
- [x] Config env vars + main.go wire с soft-fail на init.
- [x] Committed example corpus + patterns + README.
- [x] `go test ./...` зелёный.

## Дальше (roadmap)

- **PR-6.1**: integration semantic_v2 в benchmark harness.
  Опциональный `--with-embeddings` slot в `cmd/firewall-bench`,
  отдельный baseline-блок (FPR-тесты с жёсткими порогами), sidecar
  Ollama в CI.
- **PR-6.2**: `cmd/firewall-corpus-verify` — offline validation
  committed manifest без запуска backend.
- **PR-5.2**: расширенные positive.jsonl для benchmark (канонические
  attack-паттерны, чтобы baseline recall поднялся ≥0.6 после включения
  v2).
- **PR-7**: Stage 2 streaming passthrough (incremental scanning).

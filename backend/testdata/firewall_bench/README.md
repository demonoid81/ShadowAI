# Firewall FP/FN Benchmark (PR-5)

Curated datasets и committed baseline для offline, детерминистичного
бенчмарка firewall-инспекторов.

## Структура

```
testdata/firewall_bench/
├── baseline.json                       # committed thresholds
├── SOURCES.md                          # атрибуция датасетов
├── LICENSES.md                         # лицензии
├── prompt_injection/
│   ├── positive.jsonl                  # ~50 атак
│   └── negative.jsonl                  # ~50 легитимных запросов
└── jailbreak/
    ├── positive.jsonl                  # ~40 jailbreak attempts
    └── negative.jsonl                  # ~40 легитимных запросов
```

Формат jsonl:
```json
{"id":"pi-001","label":"positive","text":"...","source":"owasp-llm01","license":"CC0"}
```

Поля `id`, `label` (`positive`|`negative`) и `text` обязательны;
`source`/`license` — для атрибуции.

## Запуск

```bash
cd backend
go run ./cmd/firewall-bench --all                      # table output (local)
go run ./cmd/firewall-bench --inspector prompt_injection

# Для CI с точным exit-code контрактом (см. ниже):
go build -o firewall-bench ./cmd/firewall-bench
./firewall-bench --all --format json > bench-results.json
```

### Exit codes

- `0` — все метрики ≥ baseline thresholds (pass)
- `1` — runtime error (bad dataset, unknown inspector, IO, **missing/invalid baseline без `--allow-missing-baseline`**)
- `2` — regression: любая метрика хуже baseline

**Важно про `go run`:** когда дочерний процесс завершается с exit 2,
`go run` сам возвращает 1 и печатает `exit status 2` в stderr. Для
CI, которая должна различать exit 1 (runtime) и exit 2 (regression),
используйте **скомпилированный binary**, а не `go run`. Для merge-gate
"non-zero = fail" достаточно и `go run`, но числовой код будет
потерян.

### CLI overrides

- `--min-precision <f>` / `--min-recall <f>` / `--max-fpr <f>` —
  применяют порог ко ВСЕМ инспекторам (удобно для ad-hoc
  прогонов).
- `--baseline <path>` — альтернативный baseline.
- `--allow-missing-baseline` — **только для ad-hoc локальных прогонов**.
  Если baseline-файл не существует (os.IsNotExist), CLI продолжит с
  warning. **НЕ** снимает ошибки парсинга: corrupt/invalid JSON всегда
  даёт exit 1 (broken control plane нельзя тихо обходить).
- `--with-embeddings` — **PR-6.1**: добавляет `semantic_v2` inspector
  в прогон. Требует запущенный embedding provider и валидный corpus.
  Конфигурация читается из env-vars (см. ниже). Без флага
  `semantic_v2` НЕ запускается — offline CI не зависит от внешнего
  сервиса.

### semantic_v2 (`--with-embeddings`)

Env vars (те же имена, что в `cmd/shadowai/main.go`):
```
FIREWALL_EMBEDDING_PROVIDER=ollama
FIREWALL_EMBEDDING_ENDPOINT=http://localhost:11434
FIREWALL_EMBEDDING_MODEL=nomic-embed-text
FIREWALL_EMBEDDING_API_KEY=              # openai only
FIREWALL_EMBEDDING_DIMENSION=768
FIREWALL_EMBEDDING_TIMEOUT=10s
FIREWALL_SA_V2_CORPUS_PATH=firewall_corpus/semantic_v2.json
FIREWALL_SA_V2_THRESHOLD=0.75
FIREWALL_SA_V2_BLOCK_THRESHOLD=0.88
```

Baseline для `semantic_v2` **обязан** содержать запись с полным
metadata lock (провайдер + модель + corpus_version) **плюс** пороги:
```json
"semantic_v2": {
  "provider": "ollama",
  "model": "nomic-embed-text",
  "corpus_version": 1,
  "min_precision": 0.85,
  "min_recall": 0.60,
  "max_fpr": 0.10
}
```

**PR-6.1.1 gate** (обязательно для CI):
- если baseline **не содержит** `semantic_v2` entry → **exit 1**;
- если entry есть, но отсутствует любое из `provider`/`model`/
  `corpus_version` (или `corpus_version == 0`) → **exit 1**;
- если runtime provider/model/corpus_version **не совпадает** с
  baseline → **exit 1** (misconfig, не regression).

Для локального bootstrap (впервые разворачиваем inspector, baseline
entry ещё не создан) можно передать `--allow-missing-baseline` —
он снимет только два первых случая (отсутствующая/неполная запись).
Metadata mismatch, corrupt JSON и read-error флагом **не** снимаются.

## Separate CI slot для semantic_v2

Рекомендуемая структура CI:

```yaml
# job 1: fast offline baseline (heuristic only)
firewall-bench-offline:
  steps:
    - run: |
        cd backend
        go build -o firewall-bench ./cmd/firewall-bench
        ./firewall-bench --all --format json > bench-offline.json

# job 2: optional, требует Ollama sidecar
firewall-bench-embeddings:
  services:
    ollama:
      image: ollama/ollama:latest
      ports: [11434]
  steps:
    - run: |
        curl http://ollama:11434/api/pull -d '{"name":"nomic-embed-text"}'
        cd backend
        go run ./cmd/firewall-corpus-gen \
          --patterns ./firewall_corpus/patterns \
          --output   ./firewall_corpus/semantic_v2.json \
          --provider ollama --endpoint http://ollama:11434 \
          --model    nomic-embed-text --dimension 768
        ./firewall-bench --with-embeddings --format json > bench-emb.json
```

Offline job — blocking для merge. Embeddings job — optional или
extended pipeline (медленнее, требует GPU/CPU resources).

## CI integration

```bash
cd backend
go build -o firewall-bench ./cmd/firewall-bench
./firewall-bench --all --format json > bench-results.json
# exit 1 → runtime error (включая missing/invalid baseline) — CI fail
# exit 2 → regression — CI fail
# exit 0 → pass
```

CI-gate **обязан** требовать наличия `baseline.json` в репо — без него
любой regression не будет пойман. Это обеспечено fail-hard поведением
runner'а: missing baseline без `--allow-missing-baseline` → exit 1.

**Важно:** CI не должен модифицировать `baseline.json`. Чтобы обновить
baseline — создайте PR вручную с новыми thresholds; reviewer увидит
diff и подтвердит осознанно.

## Почему judge=nil

Инспекторы в бенчмарке конструируются с `judge=nil`: offline,
детерминистичный, не зависит от сети или LLM API. Это даёт воспроизводимые
результаты на CI и на дев-машине.

LLM-judge расширит coverage (поймает paraphrases, которые heuristic-
patterns пропустили), но его поведение зависит от провайдера/модели и
дрейфует во времени — не подходит для строгого baseline. В v2 roadmap —
отдельный bench-slot с judge-включением и слабыми FPR-порогами.

## Roadmap (v2+)

- **Расширить positive.jsonl.** Сейчас многие creative paraphrases
  не матчатся `DefaultPromptInjectionPatterns`. Пополнять параллельно
  с расширением patterns в `backend/internal/firewall/patterns.go`.
- **Добавить `content_moderation` / `pii` / `output_validation`.**
  Требуют ground-truth-меток, что само по себе дискуссия —
  делаем отдельный PR.
- **Judge-enabled bench slot.** `--with-judge` flag + отдельный
  threshold-блок в baseline.json.
- **Large-corpus слой через env** `FIREWALL_BENCH_DATA=/path/`,
  чтобы можно было натравить на OWASP/Garak полные корпуса
  без раздувания репо.

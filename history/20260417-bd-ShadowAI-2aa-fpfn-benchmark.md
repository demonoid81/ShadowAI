# bd-ShadowAI-2aa: PR-5 — FP/FN benchmark harness для firewall-инспекторов

**Дата:** 2026-04-17
**Статус:** реализовано.

## Контекст

После PR-4 / PR-4.1 firewall pipeline получил режимы исполнения
(enforce/shadow/disabled) и observability. Недостающий кусок —
**оценка качества детекции**: какое у инспекторов реальное
precision/recall на known attack patterns, и не деградировали ли
эти метрики при рефакторинге patterns/judge/multiturn-логики.

PR-5 вводит benchmark harness:
- curated JSONL-датасеты в `backend/testdata/firewall_bench/`;
- Go package `internal/firewallbench` с parse/metrics/runner/baseline;
- отдельный CLI `cmd/firewall-bench` (не `go test -tags=bench`);
- committed `baseline.json` с пороговыми значениями;
- CI-контракт: exit 2 при regression.

## Контракт

| Требование                                    | Решение                                      |
|-----------------------------------------------|----------------------------------------------|
| Data-driven, reproducible                     | JSONL в repo, `judge=nil`                    |
| CI не модифицирует repo state                 | baseline читается, не пишется                |
| Разделение thresholds и last-run данных       | baseline содержит только thresholds          |
| Чистый output для CI/human                    | `--format table \| json`                     |
| Расширяемо на новые инспекторы                | `firewallbench.Registry()` + JSONL-папка     |
| Возможность локального эксперимента           | `--min-*/--max-fpr` overrides                |

## Реализация

### Package `internal/firewallbench`

- **`metrics.go`**: `Compute(tp, fp, tn, fn) Metrics`. Защита от
  NaN/Inf во всех four метриках — критично для JSON-serialize
  (NaN невалиден по RFC 8259) и для сравнения с baseline.
- **`dataset.go`**: `LoadDataset(path) ([]Example, error)`. JSONL-парсер
  с:
  - skip пустых строк (позволяет визуальные разделители);
  - сообщение об ошибке с номером строки (для правки вручную);
  - валидация required (`id`, `label`, `text`) и whitelist label
    (`positive`|`negative`).
- **`runner.go`**: `Run(ctx, name, DetectFunc, pos, neg) Result`.
  Абстрактный `DetectFunc` позволяет unit-тестировать runner без
  зависимости от `firewall`. Порядок обхода (positive → negative)
  фиксированный для стабильных CI-diff'ов.
- **`inspectors.go`**: `NewFirewallDetector(firewall.Inspector)` —
  адаптер; `Registry()` — список factory'ов для CLI.
- **`baseline.go`**: `LoadBaseline`, `Baseline.CheckRegression` и
  `HasInspector`. Threshold==0 пропускается (partial config).
  Missing inspector in baseline → 0 regressions (warning, не error).

### CLI `cmd/firewall-bench`

- Flags: `--inspector`, `--all`, `--data`, `--baseline`, `--format`,
  `--min-precision`, `--min-recall`, `--max-fpr`.
- Exit 0 на pass, 1 на runtime error, 2 на regression.
- Table output: фиксированная колоночная ширина для diff'ов.
- JSON output: содержит `results[]`, `regressions[]`, `warnings[]` —
  удобно для dashboards.

### Committed артефакты

```
backend/testdata/firewall_bench/
  README.md
  SOURCES.md            — атрибуция датасетов
  LICENSES.md           — MIT / CC0 для canonical паттернов
  baseline.json         — thresholds с комментарием-рационале
  prompt_injection/
    positive.jsonl      — 50 атак (OWASP LLM01 + curated paraphrases)
    negative.jsonl      — 50 легитимных запросов (ru+en, техника+разговор)
  jailbreak/
    positive.jsonl      — 40 jailbreak attempts (DAN/STAN/AIM/persona)
    negative.jsonl      — 40 легитимных roleplay-запросов
```

### Baseline (MVP)

```json
{
  "prompt_injection": {"min_precision": 0.9, "min_recall": 0.2, "max_fpr": 0.05},
  "jailbreak":        {"min_precision": 0.9, "min_recall": 0.01, "max_fpr": 0.05}
}
```

Результат первого прогона:
```
prompt_injection  precision=1.0000 recall=0.2400 fpr=0.0000 f1=0.3871
jailbreak         precision=1.0000 recall=0.0250 fpr=0.0000 f1=0.0488
```

**Почему recall намеренно низкий:**
- инспекторы работают в heuristic-only (`judge=nil`, offline);
- curated dataset содержит много creative paraphrases, не покрытых
  существующими regex-patterns в `DefaultPromptInjectionPatterns`.

Baseline при этом полезен:
- ловит precision-регрессию (ошибочные false positive при добавлении
  новых patterns);
- ловит fpr-регрессию (те же paraphrases ловятся на чистых запросах);
- recall threshold сигнализирует о катастрофической деградации
  (recall < 0.2 → инспектор совсем перестал ловить canonical атаки).

Улучшение recall — roadmap в README.md.

### Тесты

- `metrics_test.go` — 4 теста (balanced, perfect, zero-div, totals).
- `dataset_test.go` — 5 тестов (happy path, skip blanks, line number
  в ошибке, required fields, label whitelist).
- `runner_test.go` — 4 теста (perfect detector, always-fires,
  never-fires, empty datasets).
- `baseline_test.go` — 7 тестов (load, pass, precision-below,
  fpr-above, multiple violations, unknown inspector, HasInspector).

Итого 20 новых tests + e2e прогон через CLI (exit 0/2 проверены
вручную).

## Размышления

- Рассмотрена альтернатива Go-test с build tag `//go:build bench`.
  Отклонена:
  - benchmark — это eval-процесс, не unit/integration test;
  - нужен table + JSON output одновременно (go test ограничен по
    формату);
  - будущий рост (baselines, per-inspector flags, CI artifacts)
    легче в CLI.
- Рассмотрен single .txt per example. Отклонён: 1000+ файлов =
  файловый шум, нет metadata. JSONL — компактно + поля source/license.
- Рассмотрено запись last-run metrics в testdata. Отклонено:
  CI не должен модифицировать repo state; baseline содержит только
  thresholds, last-run идёт в CI artifact.
- Рассмотрено писать positive.jsonl так, чтобы все точно матчились
  существующими patterns → recall~0.95 → baseline ~0.9.
  Отклонено: "curated under fit" лучше показывает реальный detection
  gap, чем искусственно подогнанный dataset; ловить precision/fpr
  regression не страдает от низкого recall (threshold = 0.2).
- Рассмотрено LLM-judge enabled в CI. Отклонено: non-deterministic,
  зависит от провайдера, дрейф во времени. В roadmap — отдельный
  bench-slot `--with-judge`.

## Definition of Done

- [x] Package `internal/firewallbench` + 20 тестов.
- [x] CLI `cmd/firewall-bench` с exit 0/1/2.
- [x] Committed datasets (90+ examples total) + SOURCES/LICENSES/README.
- [x] Committed baseline.json.
- [x] `go test ./...` зелёный; `go run ./cmd/firewall-bench --all`
      exit 0; `--min-recall 0.9` exit 2 (regression корректно сигналит).

## Roadmap (v2+)

- Расширить positive.jsonl каноническими примерами → recall
  baseline ≥0.6 (параллельно: расширить DefaultPromptInjectionPatterns).
- Добавить инспекторы `content_moderation`, `pii`, `output_validation`
  (отдельный PR — ground-truth дискуссии).
- `--with-judge` slot с weaker thresholds на FPR (judge drift).
- Large-corpus через env `FIREWALL_BENCH_DATA=/path/` — OWASP/Garak
  без раздувания репо.
- Weekly CI cron с запуском и хранением trend'а в artifact'ах
  (drift detection через неделю).

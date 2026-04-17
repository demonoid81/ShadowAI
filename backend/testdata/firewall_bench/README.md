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
go run ./cmd/firewall-bench --all                      # table output
go run ./cmd/firewall-bench --all --format json        # JSON for CI
go run ./cmd/firewall-bench --inspector prompt_injection
```

### Exit codes

- `0` — все метрики ≥ baseline thresholds (pass)
- `1` — runtime error (bad dataset, unknown inspector, IO)
- `2` — regression: любая метрика хуже baseline

### CLI overrides

- `--min-precision <f>` / `--min-recall <f>` / `--max-fpr <f>` —
  применяют порог ко ВСЕМ инспекторам (удобно для ad-hoc
  прогонов).
- `--baseline <path>` — альтернативный baseline.

## CI integration

Пример для любой CI-системы, которая поддерживает exit codes:

```yaml
- name: firewall-bench regression
  run: |
    cd backend
    go run ./cmd/firewall-bench --all --format json > bench-results.json
  # exit 2 → fail; exit 0 → pass. Артефакт bench-results.json
  # загружается отдельным шагом.
```

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

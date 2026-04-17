# bd-ShadowAI-2aa: примеры использования PR-5 benchmark

**Дата:** 2026-04-17

## Happy path 1: первый прогон на чистой ветке

```bash
$ cd backend
$ go run ./cmd/firewall-bench --all --data testdata/firewall_bench

inspector            tp   fp   tn   fn   precision  recall     fpr        f1
-------------------- ---- ---- ---- ---- ---------- ---------- ---------- ----------
prompt_injection       12    0   50   38     1.0000     0.2400     0.0000     0.3871
jailbreak               1    0   40   39     1.0000     0.0250     0.0000     0.0488
$ echo $?
0
```

Все метрики ≥ baseline (`min_precision=0.9`, `min_recall=0.2/0.01`,
`max_fpr=0.05`). Exit 0 — CI зелёный.

---

## Happy path 2: JSON output для CI artifact

```bash
$ go run ./cmd/firewall-bench --all --format json > bench-results.json
$ head -20 bench-results.json
{
  "results": [
    {
      "inspector": "prompt_injection",
      "metrics": {
        "tp": 12,
        "fp": 0,
        "tn": 50,
        "fn": 38,
        "precision": 1,
        "recall": 0.24,
        "fpr": 0,
        "f1": 0.3870967741935484
      }
    },
    ...
  ]
}
```

CI загружает этот файл как artifact; dashboard строит trend поверх
недель запусков.

---

## Happy path 3: один инспектор для быстрой итерации

При отладке регрессии в `prompt_injection`:

```bash
$ go run ./cmd/firewall-bench --inspector prompt_injection

inspector            tp   fp   tn   fn   precision  recall     fpr        f1
-------------------- ---- ---- ---- ---- ---------- ---------- ---------- ----------
prompt_injection       12    0   50   38     1.0000     0.2400     0.0000     0.3871
```

Позволяет не ждать прогона jailbreak'а.

---

## Edge case 1: regression detection

Имитация ухудшения через CLI override:

```bash
$ go run ./cmd/firewall-bench --all --min-recall 0.9
inspector            tp   fp   tn   fn   precision  recall     fpr        f1
-------------------- ---- ---- ---- ---- ---------- ---------- ---------- ----------
prompt_injection       12    0   50   38     1.0000     0.2400     0.0000     0.3871
jailbreak               1    0   40   39     1.0000     0.0250     0.0000     0.0488

REGRESSIONS:
  prompt_injection.recall: 0.2400 (threshold 0.9000)
  jailbreak.recall: 0.0250 (threshold 0.9000)
$ echo $?
2
```

Exit 2 блокирует merge в CI.

---

## Edge case 2: добавление нового инспектора без baseline

```bash
# Допустим, в Registry() добавлен content_moderation,
# но baseline.json ещё не обновлён.
$ go run ./cmd/firewall-bench --all
warning: no baseline for inspector "content_moderation" — регрессия не проверяется

inspector            tp   fp   tn   fn   precision  recall     fpr        f1
-------------------- ---- ---- ---- ---- ---------- ---------- ---------- ----------
prompt_injection       12    0   50   38     1.0000     0.2400     0.0000     0.3871
jailbreak               1    0   40   39     1.0000     0.0250     0.0000     0.0488
content_moderation      8    1   49    7     0.8889     0.5333     0.0200     0.6667
$ echo $?
0
```

Новый инспектор прогоняется, числа видны, но regression-check
пропускается до тех пор, пока оператор не добавит thresholds в
baseline.json в отдельном PR.

---

## Edge case 3: malformed dataset → runtime error (exit 1)

Допустим, кто-то добавил строку без `text`:

```bash
$ go run ./cmd/firewall-bench --all
error: testdata/firewall_bench/prompt_injection/positive.jsonl line 17: missing text
$ echo $?
1
```

Line-number в сообщении позволяет быстро локализовать и поправить.

---

## Edge case 4: отсутствующий baseline.json

```bash
$ go run ./cmd/firewall-bench --all --baseline /tmp/does-not-exist
warning: baseline /tmp/does-not-exist не найден — regression-check отключён
warning: no baseline for inspector "prompt_injection" — регрессия не проверяется
warning: no baseline for inspector "jailbreak" — регрессия не проверяется

inspector            tp   fp   tn   fn   precision  recall     fpr        f1
-------------------- ---- ---- ---- ---- ---------- ---------- ---------- ----------
prompt_injection       12    0   50   38     1.0000     0.2400     0.0000     0.3871
jailbreak               1    0   40   39     1.0000     0.0250     0.0000     0.0488
$ echo $?
0
```

CLI не падает — просто не проверяет регрессию. Полезно для локального
эксплорейшена на новом окружении.

---

## Observability example: CI workflow

```yaml
# .github/workflows/firewall-bench.yml (концепт — .github не в репо ShadowAI)
name: firewall-bench regression
on:
  pull_request:
    paths:
      - 'backend/internal/firewall/**'
      - 'backend/testdata/firewall_bench/**'
jobs:
  bench:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.25' }
      - name: run benchmark
        run: |
          cd backend
          go run ./cmd/firewall-bench --all --format json > bench-results.json
      - name: upload artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: firewall-bench-${{ github.sha }}
          path: backend/bench-results.json
```

Exit 2 автоматически fails job. Artifact доступен для анализа
независимо от pass/fail.

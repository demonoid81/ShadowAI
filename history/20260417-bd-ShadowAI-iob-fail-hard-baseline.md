# bd-ShadowAI-iob: PR-5.1 — fail-hard missing/invalid baseline + docs

**Дата:** 2026-04-17
**Статус:** реализовано.

## Контекст

PR-5 (bd-ShadowAI-2aa) внёс benchmark harness с контрактом "exit 2
блокирует merge при regression". Ревью обнаружило, что этот gate
**тихо отключается** при неверной конфигурации:

1. **Медиум-баг.** `loadBaselineWithOverrides` при любой ошибке чтения
   baseline (включая `os.IsNotExist` и invalid JSON) печатал warning,
   возвращал пустой baseline и продолжал прогон. Регрессии не писались
   → exit 0 → CI считал всё хорошим.
2. **Лоу-баг в доках.** README/CLI doccomment обещали `exit 2` при
   `go run ./cmd/firewall-bench`. На практике `go run` сам возвращает
   `1` при любом non-zero exit child-процесса (печатая `exit status 2`
   в stderr), ломая различение runtime (1) vs regression (2).

PR-5.1 чинит оба.

## Реализация

### Fail-hard по умолчанию

`loadBaselineWithOverrides` теперь возвращает `(*Baseline, string, error)`.
`run()` при non-nil error печатает message и возвращает `exitRuntime` (1).

Граница определена чётко:
- `os.IsNotExist` + `--allow-missing-baseline` → warning, пустой
  baseline, продолжить.
- `os.IsNotExist` без флага → **error с подсказкой** `"передайте
  --allow-missing-baseline для ad-hoc прогона или создайте файл для
  CI-gate"`.
- invalid JSON / permission / IO → **всегда** error, `--allow-missing-baseline`
  НЕ помогает.

Рационале границы: "missing — осознанный bootstrap-case; corrupt —
broken control plane, его нельзя тихо обходить".

### Флаг `--allow-missing-baseline`

Новый boolean flag, default `false`. Описание в help-выводе явно
говорит "ad-hoc local use only; invalid JSON is still fatal".

### Рефактор под тестируемость

`main()` стал одной строчкой: `os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))`.

`run(args, stdout, stderr) int` — чистая функция: flag.NewFlagSet
(а не глобальный flag), writers как параметры, exit-коды как
return value. Это позволяет unit-тестам проверять exit codes и
stdout/stderr content без обходных путей через `os/exec`.

### Docs

Обновлены `cmd/firewall-bench/main.go` doccomment и
`testdata/firewall_bench/README.md`:
- CI-gate пример переписан на built binary:
  ```
  go build -o firewall-bench ./cmd/firewall-bench
  ./firewall-bench --all
  ```
- добавлена заметка про поведение `go run` с non-zero exit кодом;
- описан `--allow-missing-baseline` с границами применения.

### Тесты (`cmd/firewall-bench/main_test.go`)

6 тестов (включая 1 subtest с двумя кейсами):
1. `TestRun_MissingBaseline_FailsHard` — missing без флага → exit 1,
   stderr упоминает baseline.
2. `TestRun_MissingBaseline_WithAllowFlag` — missing + флаг → exit 0,
   warning.
3. `TestRun_InvalidJSONBaseline_AlwaysFails` с двумя sub-кейсами
   (без флага и с `--allow-missing-baseline`): оба exit 1.
4. `TestRun_ValidBaseline_Passes` — smoke на committed baseline.
5. `TestRun_RegressionDetected_Exit2` — override `--min-recall 0.9`
   гарантированно триггерит регрессию на текущих метриках, exit 2 +
   `REGRESSIONS` в stdout.
6. `TestRun_NoArgs_Usage` — без `--inspector`/`--all` сразу exit 1.

### Ручная проверка (воспроизведение bug-report)

```
$ ./firewall-bench --all --baseline /tmp/no-such.json --min-recall 0.9
error: baseline /tmp/no-such.json не найден; передайте --allow-missing-baseline...
exit=1                                          # ДО PR-5.1 было 0

$ ./firewall-bench --all --baseline /tmp/no-such.json --allow-missing-baseline
warning: baseline /tmp/no-such.json не найден (--allow-missing-baseline): regression-check отключён
...
exit=0                                          # ad-hoc путь работает

$ ./firewall-bench --all --baseline /tmp/bad.json --allow-missing-baseline
error: baseline /tmp/bad.json не удалось прочитать: parse baseline ...
exit=1                                          # invalid JSON не обходится флагом
```

## Размышления

- Рассмотрено: разрешить `--allow-missing-baseline` снимать любые
  ошибки baseline. Отклонено: invalid JSON — сигнал сломанного
  control plane (частично записанный файл, битая merge-ветка,
  encoding issue); тихое его обхождение превратит PR-5.1 fix в
  ту же дыру.
- Рассмотрено: добавить `--strict-baseline` флаг и оставить текущее
  поведение по умолчанию. Отклонено: безопасный default должен быть
  fail-hard; «неожиданное тихое прохождение» — это и есть регрессия,
  которую PR-5.1 фиксит.
- Рассмотрено: `errors.Is` чтобы поддержать wrap'ы в LoadBaseline.
  Применено: `LoadBaseline` уже оборачивает через `%w`, так что
  `errors.Is(err, os.ErrNotExist)` работает корректно, без хрупкого
  `strings.Contains`.

## Definition of Done

- [x] Бага-репро: missing baseline без флага → exit 1 (было 0).
- [x] 6 юнит-тестов через `run()` — exit codes + stdout/stderr.
- [x] Invalid JSON всегда фейлит, даже с флагом.
- [x] README + doccomment указывают на built binary для точного
      exit-code контракта.
- [x] `go test ./...` — зелёный.

## Дальше

Можно переходить к **PR-6: Semantic V2 (embedding-based inspector)**.
Текущий benchmark показывает recall=0.24 для prompt_injection и
recall=0.025 для jailbreak — это не harness bug, а сигнал о detection
gap. Embedding-based слой должен этот gap значительно сократить (в
paraphrase-устойчивости). После PR-6 имеет смысл вернуться к
расширению datasets (PR-5.2 — расширенный positive.jsonl с
каноническими attack-паттернами).

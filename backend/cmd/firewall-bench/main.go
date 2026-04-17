// Command firewall-bench — FP/FN benchmark harness для firewall-инспекторов.
//
// Usage:
//
//	firewall-bench --inspector prompt_injection
//	firewall-bench --all
//	firewall-bench --all --format json > results.json
//	firewall-bench --all --baseline testdata/firewall_bench/baseline.json
//
// # Exit codes
//
//	0 — все метрики ≥ baseline thresholds
//	1 — runtime error (bad dataset, unknown inspector, IO,
//	    missing/invalid baseline без --allow-missing-baseline)
//	2 — regression detected (любая метрика хуже baseline)
//
// # CI integration
//
// Для строгого CI-gate используйте built binary, а не `go run`:
//
//	go build -o firewall-bench ./cmd/firewall-bench
//	./firewall-bench --all    # exit 2 прозрачно прокидывается из child
//
// `go run` сам возвращает 1 при любом non-zero exit дочернего процесса
// (в stderr останется "exit status 2"), что ломает различение exit 1
// (runtime) и exit 2 (regression) в CI-логике.
//
// # Baseline policy
//
// Для merge-gate CI должен требовать существующий и валидный
// `baseline.json`. Флаг `--allow-missing-baseline` предназначен ТОЛЬКО
// для ad-hoc локальных прогонов при первичном bootstrap'е инспектора:
// он снимает "no such file" (os.IsNotExist), но НЕ снимает ошибки
// парсинга — corrupt baseline трактуется как broken control plane и
// всегда даёт exit 1.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"context"

	"github.com/shadowai/backend/internal/firewallbench"
)

// Exit codes — экспортировать не требуется, но явные константы проще
// искать в коде и тестах.
const (
	exitOK         = 0
	exitRuntime    = 1
	exitRegression = 2
)

// runReport — payload для --format=json. Стабильный контракт для CI
// dashboard'ов и external tooling.
type runReport struct {
	Results     []firewallbench.Result     `json:"results"`
	Regressions []firewallbench.Regression `json:"regressions,omitempty"`
	Warnings    []string                   `json:"warnings,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run — чистое ядро CLI: принимает args + streams, возвращает exit-код.
// Выделено из main() для unit-тестирования (см. main_test.go).
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("firewall-bench", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		inspectorFlag        = fs.String("inspector", "", "run single inspector (ex: prompt_injection)")
		allFlag              = fs.Bool("all", false, "run all registered inspectors")
		dataDir              = fs.String("data", "testdata/firewall_bench", "datasets directory")
		baselinePath         = fs.String("baseline", "", "path to baseline.json (default: <data>/baseline.json)")
		allowMissingBaseline = fs.Bool("allow-missing-baseline", false,
			"skip baseline gate if file is missing (ad-hoc local use only; invalid JSON is still fatal)")
		format       = fs.String("format", "table", "output format: table | json")
		minPrecision = fs.Float64("min-precision", 0, "override baseline min_precision for all inspectors")
		minRecall    = fs.Float64("min-recall", 0, "override baseline min_recall for all inspectors")
		maxFPR       = fs.Float64("max-fpr", 0, "override baseline max_fpr for all inspectors")
	)
	if err := fs.Parse(args); err != nil {
		// flag уже напечатал usage в stderr.
		return exitRuntime
	}

	if *inspectorFlag == "" && !*allFlag {
		fmt.Fprintln(stderr, "error: either --inspector <name> or --all required")
		fs.Usage()
		return exitRuntime
	}

	registry := firewallbench.Registry()
	selected := selectInspectors(registry, *inspectorFlag, *allFlag)
	if len(selected) == 0 {
		fmt.Fprintf(stderr, "error: no matching inspectors for %q\n", *inspectorFlag)
		return exitRuntime
	}

	if *baselinePath == "" {
		*baselinePath = filepath.Join(*dataDir, "baseline.json")
	}
	baseline, warning, err := loadBaselineWithOverrides(
		*baselinePath, *allowMissingBaseline, *minPrecision, *minRecall, *maxFPR)
	if err != nil {
		// PR-5.1 fail-hard: missing без --allow-missing-baseline
		// и любая invalid-JSON/read ошибка → exit 1 с explicit error в stderr.
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitRuntime
	}

	report := runReport{}
	if warning != "" {
		report.Warnings = append(report.Warnings, warning)
	}

	ctx := context.Background()
	for _, f := range selected {
		pos, err := firewallbench.LoadDataset(filepath.Join(*dataDir, f.Name, "positive.jsonl"))
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitRuntime
		}
		neg, err := firewallbench.LoadDataset(filepath.Join(*dataDir, f.Name, "negative.jsonl"))
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitRuntime
		}

		detector := firewallbench.NewFirewallDetector(f.Make())
		result := firewallbench.Run(ctx, f.Name, detector, pos, neg)
		report.Results = append(report.Results, result)

		if !baseline.HasInspector(f.Name) {
			report.Warnings = append(report.Warnings,
				fmt.Sprintf("no baseline for inspector %q — регрессия не проверяется", f.Name))
			continue
		}
		report.Regressions = append(report.Regressions,
			baseline.CheckRegression(f.Name, result.Metrics)...)
	}

	if *format == "json" {
		printJSON(stdout, report)
	} else {
		printTable(stdout, report)
	}

	if len(report.Regressions) > 0 {
		return exitRegression
	}
	return exitOK
}

// selectInspectors применяет --inspector или --all фильтр к registry.
func selectInspectors(all []firewallbench.InspectorFactory, name string, allFlag bool) []firewallbench.InspectorFactory {
	if allFlag {
		return all
	}
	for _, f := range all {
		if f.Name == name {
			return []firewallbench.InspectorFactory{f}
		}
	}
	return nil
}

// loadBaselineWithOverrides читает baseline.json и накладывает CLI-
// override'ы (--min-precision etc) на ВСЕ инспекторы.
//
// Граница ошибок (PR-5.1):
//   - os.IsNotExist + allowMissing=true → nil error, warning, пустой baseline;
//   - os.IsNotExist + allowMissing=false → error (CI должен падать);
//   - любая другая ошибка (включая invalid JSON) → error, allowMissing
//     НЕ снимает её (corrupt control plane нельзя тихо обходить).
func loadBaselineWithOverrides(path string, allowMissing bool, minP, minR, maxFPR float64) (*firewallbench.Baseline, string, error) {
	b, err := firewallbench.LoadBaseline(path)
	var warning string
	if err != nil {
		// Разворачиваем error, чтобы добраться до underlying os.ErrNotExist
		// через errors.Is. LoadBaseline оборачивает исходную ошибку через %w.
		if errors.Is(err, os.ErrNotExist) {
			if !allowMissing {
				return nil, "", fmt.Errorf("baseline %s не найден; передайте --allow-missing-baseline для ad-hoc прогона или создайте файл для CI-gate", path)
			}
			warning = fmt.Sprintf("baseline %s не найден (--allow-missing-baseline): regression-check отключён", path)
			b = &firewallbench.Baseline{Inspectors: map[string]firewallbench.InspectorBaseline{}}
		} else {
			// Invalid JSON / permission / IO — corrupt control plane,
			// allowMissing НЕ помогает.
			return nil, "", fmt.Errorf("baseline %s не удалось прочитать: %w", path, err)
		}
	}

	if minP > 0 || minR > 0 || maxFPR > 0 {
		for name, rule := range b.Inspectors {
			if minP > 0 {
				rule.MinPrecision = minP
			}
			if minR > 0 {
				rule.MinRecall = minR
			}
			if maxFPR > 0 {
				rule.MaxFPR = maxFPR
			}
			b.Inspectors[name] = rule
		}
	}
	return b, warning, nil
}

func printJSON(w io.Writer, r runReport) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r)
}

func printTable(w io.Writer, r runReport) {
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "warning: %s\n", warn)
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "inspector            tp   fp   tn   fn   precision  recall     fpr        f1")
	fmt.Fprintln(w, "-------------------- ---- ---- ---- ---- ---------- ---------- ---------- ----------")
	for _, res := range r.Results {
		m := res.Metrics
		fmt.Fprintf(w, "%-20s %4d %4d %4d %4d %10.4f %10.4f %10.4f %10.4f\n",
			res.Inspector, m.TP, m.FP, m.TN, m.FN,
			m.Precision, m.Recall, m.FPR, m.F1)
	}

	if len(r.Regressions) > 0 {
		fmt.Fprintln(w, "\nREGRESSIONS:")
		for _, reg := range r.Regressions {
			fmt.Fprintf(w, "  %s.%s: %.4f (threshold %.4f)\n",
				reg.Inspector, reg.Field, reg.Actual, reg.Threshold)
		}
	}
}

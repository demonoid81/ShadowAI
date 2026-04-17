// Command firewall-bench — FP/FN benchmark harness для firewall-инспекторов.
//
// Usage:
//
//	firewall-bench --inspector prompt_injection
//	firewall-bench --all
//	firewall-bench --all --format json > results.json
//	firewall-bench --all --baseline testdata/firewall_bench/baseline.json
//
// Exit codes:
//
//	0 — все метрики ≥ baseline thresholds
//	1 — runtime error (bad dataset, unknown inspector, IO)
//	2 — regression detected (любая метрика хуже baseline)
//
// CI integration:
//
//	cd backend && go run ./cmd/firewall-bench --all
//	→ exit 2 блокирует merge
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/shadowai/backend/internal/firewallbench"
)

// runReport — что CLI печатает в --format=json. Публичный контракт для
// внешних dashboard'ов и CI artifact'ов.
type runReport struct {
	Results     []firewallbench.Result       `json:"results"`
	Regressions []firewallbench.Regression   `json:"regressions,omitempty"`
	Warnings    []string                     `json:"warnings,omitempty"`
}

func main() {
	var (
		inspectorFlag = flag.String("inspector", "", "run single inspector (ex: prompt_injection)")
		allFlag       = flag.Bool("all", false, "run all registered inspectors")
		dataDir       = flag.String("data", "testdata/firewall_bench", "datasets directory")
		baselinePath  = flag.String("baseline", "", "path to baseline.json (default: <data>/baseline.json)")
		format        = flag.String("format", "table", "output format: table | json")
		minPrecision  = flag.Float64("min-precision", 0, "override baseline min_precision for all inspectors")
		minRecall     = flag.Float64("min-recall", 0, "override baseline min_recall for all inspectors")
		maxFPR        = flag.Float64("max-fpr", 0, "override baseline max_fpr for all inspectors")
	)
	flag.Parse()

	if *inspectorFlag == "" && !*allFlag {
		fmt.Fprintln(os.Stderr, "error: either --inspector <name> or --all required")
		flag.Usage()
		os.Exit(1)
	}

	registry := firewallbench.Registry()
	selected := selectInspectors(registry, *inspectorFlag, *allFlag)
	if len(selected) == 0 {
		fmt.Fprintf(os.Stderr, "error: no matching inspectors for %q\n", *inspectorFlag)
		os.Exit(1)
	}

	if *baselinePath == "" {
		*baselinePath = filepath.Join(*dataDir, "baseline.json")
	}
	baseline, warning := loadBaselineWithOverrides(*baselinePath, *minPrecision, *minRecall, *maxFPR)

	report := runReport{}
	if warning != "" {
		report.Warnings = append(report.Warnings, warning)
	}

	ctx := context.Background()
	for _, f := range selected {
		pos, err := firewallbench.LoadDataset(filepath.Join(*dataDir, f.Name, "positive.jsonl"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		neg, err := firewallbench.LoadDataset(filepath.Join(*dataDir, f.Name, "negative.jsonl"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
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
		printJSON(os.Stdout, report)
	} else {
		printTable(os.Stdout, report)
	}

	if len(report.Regressions) > 0 {
		os.Exit(2)
	}
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
// override'ы (--min-precision etc) на ВСЕ инспекторы. Если файла нет,
// возвращает пустой baseline с warning (бенчмарк всё ещё выполнится,
// но regression-check пропускается).
//
// Причина "override на все": CLI-overrides предназначены для ad-hoc
// прогонов и CI-эксперимента, где оператор задаёт единый порог для
// всей кампании тестирования.
func loadBaselineWithOverrides(path string, minP, minR, maxFPR float64) (*firewallbench.Baseline, string) {
	b, err := firewallbench.LoadBaseline(path)
	var warning string
	if err != nil {
		if os.IsNotExist(err) {
			warning = fmt.Sprintf("baseline %s не найден — regression-check отключён", path)
		} else {
			warning = fmt.Sprintf("не удалось прочитать baseline: %v", err)
		}
		b = &firewallbench.Baseline{Inspectors: map[string]firewallbench.InspectorBaseline{}}
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
	return b, warning
}

func printJSON(w *os.File, r runReport) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r)
}

func printTable(w *os.File, r runReport) {
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

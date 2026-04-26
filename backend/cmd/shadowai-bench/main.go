// cmd/shadowai-bench — Scale1: ShadowAI performance measurement harness.
//
// Runs reproducible microbenchmarks and reports latency percentiles and throughput.
// Does NOT require external LLM providers — all providers are faked/mocked.
// Does NOT require a real database unless --suite includes audit-db.
//
// Usage:
//
//	shadowai-bench --suite all --samples 2000 --warmup 200 --format json
//	shadowai-bench --suite governance --samples 5000 --format table
//	shadowai-bench --suite streaming --warmup 100 --samples 1000 --format json --output baseline.json
//
// Build:
//
//	go build ./cmd/shadowai-bench
//	go build -tags enterprise ./cmd/shadowai-bench  # includes governance+SIEM benches
//
// Exit codes: 0 = completed; 2 = config error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/shadowai/backend/perf"
)

const (
	exitOK    = 0
	exitError = 2
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("shadowai-bench", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		suite   = fs.String("suite", "all", "Benchmark suite: all|chain|streaming|governance|siem (enterprise only for governance/siem)")
		samples = fs.Int("samples", 1000, "Number of measured iterations per benchmark")
		warmup  = fs.Int("warmup", 100, "Warmup iterations before measurement (not counted)")
		format  = fs.String("format", "table", `Output format: "table" or "json"`)
		output  = fs.String("output", "", "Write JSON results to file (default: stdout)")
		short   = fs.Bool("short", false, "Run fewer iterations for CI smoke check (overrides --samples to 100, --warmup to 10)")
	)
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	switch *format {
	case "table", "json":
	default:
		fmt.Fprintf(os.Stderr, "config error: --format must be table or json, got %q\n", *format)
		return exitError
	}

	if *short {
		*samples = 100
		*warmup = 10
	}

	runner := &perf.Runner{Warmup: *warmup, Samples: *samples}

	// Collect benchmark results from selected suites.
	var results []perf.BenchResult
	suites := strings.Split(*suite, ",")
	for _, s := range suites {
		s = strings.TrimSpace(s)
		switch s {
		case "all", "chain":
			results = append(results, runChainBenches(runner)...)
		}
		switch s {
		case "all", "streaming":
			results = append(results, runStreamingBenches(runner)...)
		}
		switch s {
		case "all", "governance":
			results = append(results, runGovernanceBenches(runner)...)
		}
		switch s {
		case "all", "siem":
			results = append(results, runSIEMBenches(runner)...)
		}
	}

	// Build report.
	report := buildReport(*suite, *samples, *warmup, results)

	// Output.
	switch *format {
	case "table":
		perf.PrintTable(os.Stdout, results)
		fmt.Fprintf(os.Stdout, "\nRun at: %s | Go: %s | OS: %s/%s | Samples/bench: %d\n",
			report.RunAt.Format(time.RFC3339), runtime.Version(), runtime.GOOS, runtime.GOARCH, *samples)
	case "json":
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error encoding JSON: %v\n", err)
			return exitError
		}
		if *output != "" {
			if err := os.WriteFile(*output, data, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
				return exitError
			}
			fmt.Fprintf(os.Stderr, "[shadowai-bench] results written to %s\n", *output)
		} else {
			fmt.Println(string(data))
		}
	}

	return exitOK
}

// BenchReport is the top-level JSON output structure.
type BenchReport struct {
	RunAt       time.Time        `json:"run_at"`
	GoVersion   string           `json:"go_version"`
	OS          string           `json:"os"`
	Arch        string           `json:"arch"`
	Suite       string           `json:"suite"`
	SamplesEach int              `json:"samples_each"`
	WarmupEach  int              `json:"warmup_each"`
	Results     []perf.BenchResult `json:"results"`
	Caveats     []string         `json:"caveats"`
}

func buildReport(suite string, samples, warmup int, results []perf.BenchResult) BenchReport {
	return BenchReport{
		RunAt:       time.Now().UTC(),
		GoVersion:   runtime.Version(),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Suite:       suite,
		SamplesEach: samples,
		WarmupEach:  warmup,
		Results:     results,
		Caveats: []string{
			"All numbers are in-process microbenchmarks on synthetic workloads.",
			"No real LLM providers or external databases used (unless --suite includes audit-db).",
			"Wall-clock latency includes Go scheduler jitter; run on quiet host for best accuracy.",
			"Governance benchmarks use simulated 1ms DB latency for miss path.",
			"SIEM backpressure benchmark uses httptest server on localhost; not production SIEM.",
			"Results vary with hardware, OS, and concurrent load. Label as 'target' in SLAs.",
			"See docs/performance-baseline.md for baseline and methodology.",
		},
	}
}

func runChainBenches(r *perf.Runner) []perf.BenchResult {
	return []perf.BenchResult{
		perf.ChainHMACVerify(r),
		perf.ChainAnchorSign(r),
		perf.ChainAnchorVerify(r),
	}
}

func runStreamingBenches(r *perf.Runner) []perf.BenchResult {
	return []perf.BenchResult{
		perf.StreamingDecodeEmit(r),
		perf.StreamingDecodeOnly(r),
		perf.StreamingEmitSanitized(r),
		perf.StreamingEmitVsSanitize(r),
	}
}

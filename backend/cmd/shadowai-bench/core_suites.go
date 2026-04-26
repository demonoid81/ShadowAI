//go:build !enterprise

package main

import "github.com/shadowai/backend/perf"

func runGovernanceBenches(_ *perf.Runner) []perf.BenchResult {
	return []perf.BenchResult{{
		Name:        "GovernanceBenches",
		Description: "Skipped: governance benchmarks require -tags enterprise",
		Notes:       "build with: go build -tags enterprise ./cmd/shadowai-bench",
	}}
}

func runSIEMBenches(_ *perf.Runner) []perf.BenchResult {
	return []perf.BenchResult{{
		Name:        "SIEMBenches",
		Description: "Skipped: SIEM benchmarks require -tags enterprise",
		Notes:       "build with: go build -tags enterprise ./cmd/shadowai-bench",
	}}
}

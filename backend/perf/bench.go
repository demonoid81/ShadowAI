// Package perf provides measurement primitives and benchmark implementations
// for the ShadowAI performance harness (Scale1).
//
// Build tag: none — this package is always buildable.
// The heavy benchmark loops are isolated to cmd/shadowai-bench.
//
// Usage via CLI:
//
//	shadowai-bench --suite all --samples 2000 --format json --output baseline.json
//	shadowai-bench --suite governance --samples 5000 --warmup 200 --format table
package perf

import (
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// errBenchFailed is a sentinel error for benchmark result mismatch.
var errBenchFailed = errors.New("perf: benchmark result was unexpected")

// BenchResult holds the statistics for one benchmark run.
type BenchResult struct {
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	Samples      int     `json:"samples"`
	DurationMs   float64 `json:"duration_ms"`
	ThroughputPS float64 `json:"throughput_per_sec"` // requests or events per second
	Latency      Latency `json:"latency_ms"`
	Errors       int     `json:"errors"`
	BytesEmitted int64   `json:"bytes_emitted,omitempty"`
	Notes        string  `json:"notes,omitempty"`
}

// Latency holds percentile latency in milliseconds.
type Latency struct {
	P50  float64 `json:"p50"`
	P95  float64 `json:"p95"`
	P99  float64 `json:"p99"`
	Min  float64 `json:"min"`
	Max  float64 `json:"max"`
	Mean float64 `json:"mean"`
}

// ComputeLatency sorts samples (nanoseconds) and computes percentile statistics.
func ComputeLatency(nanos []int64) Latency {
	if len(nanos) == 0 {
		return Latency{}
	}
	sorted := make([]int64, len(nanos))
	copy(sorted, nanos)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	toMS := func(ns int64) float64 { return float64(ns) / 1e6 }
	pct := func(p float64) float64 {
		idx := int(math.Ceil(p/100.0*float64(len(sorted)))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sorted) {
			idx = len(sorted) - 1
		}
		return toMS(sorted[idx])
	}
	var sum int64
	for _, v := range sorted {
		sum += v
	}
	return Latency{
		P50:  pct(50),
		P95:  pct(95),
		P99:  pct(99),
		Min:  toMS(sorted[0]),
		Max:  toMS(sorted[len(sorted)-1]),
		Mean: float64(sum) / float64(len(sorted)) / 1e6,
	}
}

// Runner runs a benchmark function for the given number of warmup and sample
// iterations, collecting per-call latency in nanoseconds.
//
// fn must return the bytes emitted (for streaming benchmarks) and an error
// (counted but does not stop the run).
type Runner struct {
	Warmup  int // warmup iterations (not counted)
	Samples int // measured iterations
}

// Run executes fn and returns a BenchResult.
func (r *Runner) Run(name, desc string, fn func() (bytesEmitted int64, err error)) BenchResult {
	// Warmup.
	for i := 0; i < r.Warmup; i++ {
		_, _ = fn()
	}

	nanos := make([]int64, 0, r.Samples)
	var totalBytes int64
	var errCount int

	start := time.Now()
	for i := 0; i < r.Samples; i++ {
		t0 := time.Now()
		b, err := fn()
		elapsed := time.Since(t0).Nanoseconds()
		nanos = append(nanos, elapsed)
		totalBytes += b
		if err != nil {
			errCount++
		}
	}
	totalDuration := time.Since(start)

	lat := ComputeLatency(nanos)
	tps := 0.0
	if totalDuration > 0 {
		tps = float64(r.Samples) / totalDuration.Seconds()
	}
	return BenchResult{
		Name:         name,
		Description:  desc,
		Samples:      r.Samples,
		DurationMs:   float64(totalDuration.Milliseconds()),
		ThroughputPS: tps,
		Latency:      lat,
		Errors:       errCount,
		BytesEmitted: totalBytes,
	}
}

// PrintTable writes results as a human-readable table to w.
func PrintTable(w io.Writer, results []BenchResult) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintln(tw, "BENCHMARK\tSAMPLES\tP50ms\tP95ms\tP99ms\tRPS\tERRORS\tBYTES\tNOTES")
	fmt.Fprintln(tw, strings.Repeat("-", 9)+"\t"+strings.Repeat("-", 7)+"\t"+strings.Repeat("-", 5)+"\t"+strings.Repeat("-", 5)+"\t"+strings.Repeat("-", 5)+"\t"+strings.Repeat("-", 8)+"\t"+strings.Repeat("-", 6)+"\t"+strings.Repeat("-", 5)+"\t"+strings.Repeat("-", 5))
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%d\t%.3f\t%.3f\t%.3f\t%.1f\t%d\t%d\t%s\n",
			r.Name, r.Samples,
			r.Latency.P50, r.Latency.P95, r.Latency.P99,
			r.ThroughputPS, r.Errors, r.BytesEmitted, r.Notes)
	}
}

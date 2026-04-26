package perf

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
)

// ── Baseline schema ────────────────────────────────────────────────────────

// BaselineFile is the versioned baseline stored in the repository.
type BaselineFile struct {
	SchemaVersion   string          `json:"schema_version"`
	UpdatedAt       string          `json:"updated_at"`
	EnvironmentNote string          `json:"environment_note"`
	Benchmarks      []BaselineEntry `json:"benchmarks"`
}

// BaselineEntry defines the threshold for one (benchmark, metric) pair.
type BaselineEntry struct {
	Name              string  `json:"name"`
	Metric            string  `json:"metric"`             // "throughput_rps"|"p50_latency_ms"|"p95_latency_ms"|"p99_latency_ms"
	Direction         string  `json:"direction"`          // "higher_is_better"|"lower_is_better"
	BaselineValue     float64 `json:"baseline_value"`     // reference value
	WarnRegressionPct float64 `json:"warn_regression_pct"` // warn if delta >= this %
	FailRegressionPct float64 `json:"fail_regression_pct"` // fail if delta >= this %
	MinSamples        int     `json:"min_samples"`
	Notes             string  `json:"notes,omitempty"`
}

// ── Comparison result ──────────────────────────────────────────────────────

// CompareStatus is the verdict for one baseline entry.
type CompareStatus string

const (
	StatusOK      CompareStatus = "ok"
	StatusImprove CompareStatus = "improve" // better than baseline
	StatusWarn    CompareStatus = "warn"
	StatusFail    CompareStatus = "fail"
	StatusMissing CompareStatus = "missing" // no current result for this bench
	StatusErrors  CompareStatus = "errors"  // errors > 0 in current result
	StatusSkipped CompareStatus = "skipped" // insufficient samples
)

// CompareResult is the output for one (benchmark, metric) comparison.
type CompareResult struct {
	Name          string        `json:"name"`
	Metric        string        `json:"metric"`
	CurrentValue  float64       `json:"current_value"`
	BaselineValue float64       `json:"baseline_value"`
	DeltaPct      float64       `json:"delta_pct"`
	Status        CompareStatus `json:"status"`
	Reason        string        `json:"reason"`
}

// CompareReport is the full comparison output.
type CompareReport struct {
	BaselineFile string          `json:"baseline_file"`
	Suite        string          `json:"suite"`
	Results      []CompareResult `json:"results"`
	Summary      CompareSummary  `json:"summary"`
}

// CompareSummary counts results by status.
type CompareSummary struct {
	OK       int `json:"ok"`
	Improve  int `json:"improve"`
	Warn     int `json:"warn"`
	Fail     int `json:"fail"`
	Missing  int `json:"missing"`
	Errors   int `json:"errors"`
	Skipped  int `json:"skipped"`
	HasFail  bool `json:"has_fail"`
}

// ── Comparison logic ───────────────────────────────────────────────────────

// Compare compares BenchResults against a BaselineFile and returns a CompareReport.
func Compare(baselineFile string, results []BenchResult) (*CompareReport, error) {
	data, err := os.ReadFile(baselineFile)
	if err != nil {
		return nil, fmt.Errorf("read baseline %s: %w", baselineFile, err)
	}
	var baseline BaselineFile
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", baselineFile, err)
	}

	// Index current results by name.
	currentByName := make(map[string]*BenchResult, len(results))
	for i := range results {
		currentByName[results[i].Name] = &results[i]
	}

	report := &CompareReport{
		BaselineFile: baselineFile,
	}

	for _, entry := range baseline.Benchmarks {
		current, ok := currentByName[entry.Name]
		if !ok {
			report.Results = append(report.Results, CompareResult{
				Name:          entry.Name,
				Metric:        entry.Metric,
				BaselineValue: entry.BaselineValue,
				Status:        StatusMissing,
				Reason:        "no current result for this benchmark (renamed or skipped)",
			})
			continue
		}

		// Errors in result → always fail.
		if current.Errors > 0 {
			report.Results = append(report.Results, CompareResult{
				Name:         entry.Name,
				Metric:       entry.Metric,
				CurrentValue: extractMetric(current, entry.Metric),
				Status:       StatusErrors,
				Reason:       fmt.Sprintf("benchmark reported %d error(s); any error is a fail", current.Errors),
			})
			continue
		}

		// Insufficient samples.
		if current.Samples < entry.MinSamples {
			report.Results = append(report.Results, CompareResult{
				Name:          entry.Name,
				Metric:        entry.Metric,
				CurrentValue:  extractMetric(current, entry.Metric),
				BaselineValue: entry.BaselineValue,
				Status:        StatusSkipped,
				Reason:        fmt.Sprintf("only %d samples (min required: %d)", current.Samples, entry.MinSamples),
			})
			continue
		}

		currentVal := extractMetric(current, entry.Metric)
		report.Results = append(report.Results, compareOne(entry, currentVal))
	}

	// Build summary.
	for _, r := range report.Results {
		switch r.Status {
		case StatusOK:
			report.Summary.OK++
		case StatusImprove:
			report.Summary.Improve++
		case StatusWarn:
			report.Summary.Warn++
		case StatusFail:
			report.Summary.Fail++
			report.Summary.HasFail = true
		case StatusMissing:
			report.Summary.Missing++
		case StatusErrors:
			report.Summary.Errors++
			report.Summary.HasFail = true
		case StatusSkipped:
			report.Summary.Skipped++
		}
	}

	return report, nil
}

// compareOne computes the CompareResult for one entry.
func compareOne(entry BaselineEntry, currentVal float64) CompareResult {
	r := CompareResult{
		Name:          entry.Name,
		Metric:        entry.Metric,
		CurrentValue:  currentVal,
		BaselineValue: entry.BaselineValue,
	}

	if entry.BaselineValue == 0 {
		r.Status = StatusSkipped
		r.Reason = "baseline_value is 0; cannot compute delta"
		return r
	}

	// Compute regression delta (positive = regression, negative = improvement).
	var deltaPct float64
	switch entry.Direction {
	case "lower_is_better":
		// Latency: increase is regression.
		deltaPct = (currentVal - entry.BaselineValue) / entry.BaselineValue * 100
	case "higher_is_better":
		// Throughput: decrease is regression.
		deltaPct = (entry.BaselineValue - currentVal) / entry.BaselineValue * 100
	default:
		r.Status = StatusSkipped
		r.Reason = fmt.Sprintf("unknown direction %q; expected lower_is_better|higher_is_better", entry.Direction)
		return r
	}

	r.DeltaPct = math.Round(deltaPct*10) / 10 // round to 1 decimal

	switch {
	case deltaPct < 0:
		r.Status = StatusImprove
		r.Reason = fmt.Sprintf("%s improved by %.1f%% (baseline=%.4f, current=%.4f)",
			entry.Metric, -deltaPct, entry.BaselineValue, currentVal)
	case deltaPct >= entry.FailRegressionPct:
		r.Status = StatusFail
		r.Reason = fmt.Sprintf("%s regressed by %.1f%% ≥ fail threshold %.0f%% (baseline=%.4f, current=%.4f)",
			entry.Metric, deltaPct, entry.FailRegressionPct, entry.BaselineValue, currentVal)
	case deltaPct >= entry.WarnRegressionPct:
		r.Status = StatusWarn
		r.Reason = fmt.Sprintf("%s regressed by %.1f%% ≥ warn threshold %.0f%% (baseline=%.4f, current=%.4f)",
			entry.Metric, deltaPct, entry.WarnRegressionPct, entry.BaselineValue, currentVal)
	default:
		r.Status = StatusOK
		r.Reason = fmt.Sprintf("%s within tolerance: +%.1f%% (warn=%.0f%%, fail=%.0f%%)",
			entry.Metric, deltaPct, entry.WarnRegressionPct, entry.FailRegressionPct)
	}
	return r
}

// extractMetric returns the numeric value for the named metric from a BenchResult.
func extractMetric(r *BenchResult, metric string) float64 {
	switch metric {
	case "throughput_rps":
		return r.ThroughputPS
	case "p50_latency_ms":
		return r.Latency.P50
	case "p95_latency_ms":
		return r.Latency.P95
	case "p99_latency_ms":
		return r.Latency.P99
	case "mean_latency_ms":
		return r.Latency.Mean
	}
	return 0
}

// PrintCompareTable writes a human-readable comparison table to w.
func PrintCompareTable(w interface{ Write([]byte) (int, error) }, report *CompareReport) {
	lines := []string{
		fmt.Sprintf("Baseline: %s", report.BaselineFile),
		fmt.Sprintf("%-40s %-20s %-10s %-10s %-8s %-8s %s",
			"BENCHMARK", "METRIC", "CURRENT", "BASELINE", "DELTA%", "STATUS", "REASON"),
		strings.Repeat("-", 130),
	}
	for _, r := range report.Results {
		statusStr := string(r.Status)
		switch r.Status {
		case StatusFail, StatusErrors:
			statusStr = "FAIL"
		case StatusWarn:
			statusStr = "WARN"
		case StatusImprove:
			statusStr = "IMPROVE"
		}
		reason := r.Reason
		if len(reason) > 60 {
			reason = reason[:57] + "..."
		}
		lines = append(lines, fmt.Sprintf("%-40s %-20s %-10.4f %-10.4f %-8.1f %-8s %s",
			r.Name, r.Metric, r.CurrentValue, r.BaselineValue, r.DeltaPct, statusStr, reason))
	}
	lines = append(lines, strings.Repeat("-", 130))
	lines = append(lines, fmt.Sprintf(
		"Summary: ok=%d improve=%d warn=%d fail=%d errors=%d missing=%d skipped=%d  HasFail=%v",
		report.Summary.OK, report.Summary.Improve, report.Summary.Warn,
		report.Summary.Fail, report.Summary.Errors, report.Summary.Missing,
		report.Summary.Skipped, report.Summary.HasFail))

	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}

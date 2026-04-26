package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/shadowai/backend/perf"
)

// TestRun_InvalidFormat verifies config error path.
func TestRun_InvalidFormat(t *testing.T) {
	code := run([]string{"--format", "xml", "--suite", "chain"})
	if code != exitError {
		t.Errorf("invalid format: exit=%d, want exitError(%d)", code, exitError)
	}
}

// TestRun_Short_Chain verifies the chain suite compiles and exits 0.
func TestRun_Short_Chain(t *testing.T) {
	code := run([]string{"--suite", "chain", "--short", "--format", "table"})
	if code != exitOK {
		t.Errorf("chain short: exit=%d, want exitOK(%d)", code, exitOK)
	}
}

// TestRun_Short_Streaming verifies the streaming suite compiles and exits 0.
func TestRun_Short_Streaming(t *testing.T) {
	code := run([]string{"--suite", "streaming", "--short", "--format", "table"})
	if code != exitOK {
		t.Errorf("streaming short: exit=%d, want exitOK(%d)", code, exitOK)
	}
}

// TestRun_JSONOutput verifies JSON output is valid and contains expected fields.
func TestRun_JSONOutput(t *testing.T) {
	outFile := t.TempDir() + "/bench.json"
	code := run([]string{
		"--suite", "chain",
		"--short",
		"--format", "json",
		"--output", outFile,
	})
	if code != exitOK {
		t.Fatalf("json output: exit=%d", code)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var report BenchReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(report.Results) == 0 {
		t.Error("results list is empty")
	}
	if len(report.Caveats) == 0 {
		t.Error("caveats list is empty")
	}
	for _, r := range report.Results {
		if r.Name == "" {
			t.Error("result has empty name")
		}
		if r.Samples == 0 {
			continue // skipped bench
		}
		if r.Latency.P50 <= 0 {
			t.Errorf("result %s: p50 = %v, want > 0", r.Name, r.Latency.P50)
		}
	}
}

// TestRun_StreamingBytesEmitted verifies streaming benchmarks report non-zero bytes.
func TestRun_StreamingBytesEmitted(t *testing.T) {
	outFile := t.TempDir() + "/stream.json"
	run([]string{"--suite", "streaming", "--short", "--format", "json", "--output", outFile})

	data, _ := os.ReadFile(outFile)
	var report BenchReport
	json.Unmarshal(data, &report) //nolint:errcheck

	for _, r := range report.Results {
		if r.Name == "StreamingDecodeEmit" && r.BytesEmitted == 0 {
			t.Errorf("StreamingDecodeEmit: bytes_emitted=0, want >0 (compiler must not optimize away work)")
		}
		if r.Name == "StreamingEmitSanitized" && r.BytesEmitted == 0 {
			t.Errorf("StreamingEmitSanitized: bytes_emitted=0, want >0")
		}
	}
}

// TestRun_Compare_OK verifies --compare exits 0 when all results are within thresholds.
func TestRun_Compare_OK(t *testing.T) {
	// Write a minimal baseline that the chain bench will easily pass.
	baselineJSON := `{
		"schema_version":"1",
		"updated_at":"2026-04-26",
		"environment_note":"test",
		"benchmarks":[
			{"name":"ChainHMACVerify","metric":"throughput_rps","direction":"higher_is_better",
			 "baseline_value":1,"warn_regression_pct":50,"fail_regression_pct":80,"min_samples":10}
		]
	}`
	baselineFile := t.TempDir() + "/baseline.json"
	if err := os.WriteFile(baselineFile, []byte(baselineJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	code := run([]string{
		"--suite", "chain", "--short", "--format", "table",
		"--compare", baselineFile,
	})
	if code != exitOK {
		t.Errorf("compare OK: exit=%d, want exitOK(%d)", code, exitOK)
	}
}

// TestRun_Compare_Fail verifies --compare exits 1 when a benchmark fails thresholds.
func TestRun_Compare_Fail(t *testing.T) {
	// Baseline with impossibly high baseline value → current will be lower → regression.
	baselineJSON := `{
		"schema_version":"1",
		"updated_at":"2026-04-26",
		"environment_note":"test",
		"benchmarks":[
			{"name":"ChainHMACVerify","metric":"throughput_rps","direction":"higher_is_better",
			 "baseline_value":99999999999,"warn_regression_pct":1,"fail_regression_pct":2,"min_samples":10}
		]
	}`
	baselineFile := t.TempDir() + "/baseline-fail.json"
	os.WriteFile(baselineFile, []byte(baselineJSON), 0o644)

	code := run([]string{
		"--suite", "chain", "--short", "--format", "table",
		"--compare", baselineFile,
	})
	if code != exitFail {
		t.Errorf("compare Fail: exit=%d, want exitFail(%d)", code, exitFail)
	}
}

// TestRun_Compare_MissingBenchmark verifies missing benchmark is warn, not fail.
func TestRun_Compare_MissingBenchmark(t *testing.T) {
	// Baseline references a benchmark that doesn't exist → missing → warn only.
	baselineJSON := `{
		"schema_version":"1",
		"updated_at":"2026-04-26",
		"environment_note":"test",
		"benchmarks":[
			{"name":"NonExistentBenchmark","metric":"throughput_rps","direction":"higher_is_better",
			 "baseline_value":1000,"warn_regression_pct":50,"fail_regression_pct":80,"min_samples":10}
		]
	}`
	baselineFile := t.TempDir() + "/baseline-missing.json"
	os.WriteFile(baselineFile, []byte(baselineJSON), 0o644)

	code := run([]string{
		"--suite", "chain", "--short", "--format", "table",
		"--compare", baselineFile,
	})
	// Missing → warn only → exit 0.
	if code != exitOK {
		t.Errorf("compare missing: exit=%d, want exitOK (missing is warn not fail)", code)
	}
}

// TestRun_Compare_CompareOutput verifies --compare-output writes JSON.
func TestRun_Compare_CompareOutput(t *testing.T) {
	baselineJSON := `{
		"schema_version":"1","updated_at":"2026-04-26","environment_note":"test",
		"benchmarks":[
			{"name":"ChainHMACVerify","metric":"throughput_rps","direction":"higher_is_better",
			 "baseline_value":1,"warn_regression_pct":50,"fail_regression_pct":80,"min_samples":10}
		]
	}`
	baselineFile := t.TempDir() + "/baseline.json"
	compareOut := t.TempDir() + "/compare-report.json"
	os.WriteFile(baselineFile, []byte(baselineJSON), 0o644)

	code := run([]string{
		"--suite", "chain", "--short", "--format", "table",
		"--compare", baselineFile,
		"--compare-output", compareOut,
	})
	if code != exitOK {
		t.Fatalf("compare output: exit=%d", code)
	}

	data, err := os.ReadFile(compareOut)
	if err != nil {
		t.Fatalf("read compare-output: %v", err)
	}
	var report perf.CompareReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal compare report: %v", err)
	}
	if len(report.Results) == 0 {
		t.Error("compare report has no results")
	}
}

// TestComputeLatency_Percentiles verifies p50/p95/p99 calculation correctness.
func TestComputeLatency_Percentiles(t *testing.T) {
	// 100 samples: 1ms to 100ms.
	nanos := make([]int64, 100)
	for i := range nanos {
		nanos[i] = int64(i+1) * 1_000_000 // 1ms..100ms in nanoseconds
	}
	lat := perf.ComputeLatency(nanos)
	if lat.P50 < 49 || lat.P50 > 51 {
		t.Errorf("P50 = %.2f ms, want ~50ms", lat.P50)
	}
	if lat.P95 < 94 || lat.P95 > 96 {
		t.Errorf("P95 = %.2f ms, want ~95ms", lat.P95)
	}
	if lat.P99 < 98 || lat.P99 > 100 {
		t.Errorf("P99 = %.2f ms, want ~99ms", lat.P99)
	}
}

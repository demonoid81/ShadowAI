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

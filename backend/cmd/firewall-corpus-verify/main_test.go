package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeVerifyCorpus(t *testing.T, dir string, overrides map[string]any) string {
	t.Helper()
	manifest := map[string]any{
		"version":      1,
		"provider":     "ollama",
		"model":        "nomic-embed-text",
		"dimension":    2,
		"normalized":   true,
		"generated_at": "2026-04-28T00:00:00Z",
		"items": []map[string]any{
			{"id": "prompt_injection-001", "category": "prompt_injection", "text": "ignore previous", "embedding": []float64{1, 0}},
			{"id": "jailbreak-001", "category": "jailbreak", "text": "dan mode", "embedding": []float64{0, 1}},
		},
	}
	for k, v := range overrides {
		manifest[k] = v
	}
	b, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "semantic_v2.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRun_ValidCorpus_JSON(t *testing.T) {
	path := writeVerifyCorpus(t, t.TempDir(), nil)
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"--corpus", path,
		"--expect-provider", "ollama",
		"--expect-model", "nomic-embed-text",
		"--expect-dimension", "2",
		"--min-items", "2",
		"--require-category", "prompt_injection",
		"--require-category", "jailbreak",
		"--format", "json",
	}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("exit = %d, want 0\nstderr=%s", code, stderr.String())
	}
	var report verifyReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}
	if !report.OK || report.Provider != "ollama" || report.Items != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if len(report.Categories) != 2 {
		t.Fatalf("categories = %+v", report.Categories)
	}
}

func TestRun_MissingCorpusFlag_ConfigError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != exitConfig {
		t.Fatalf("exit = %d, want %d", code, exitConfig)
	}
	if !strings.Contains(stderr.String(), "--corpus") {
		t.Fatalf("stderr should mention --corpus: %s", stderr.String())
	}
}

func TestRun_ProviderMismatch_FailsValidation(t *testing.T) {
	path := writeVerifyCorpus(t, t.TempDir(), nil)
	var stdout, stderr bytes.Buffer
	code := run([]string{"--corpus", path, "--expect-provider", "openai"}, &stdout, &stderr)
	if code != exitValidation {
		t.Fatalf("exit = %d, want %d", code, exitValidation)
	}
	if !strings.Contains(stderr.String(), "provider mismatch") {
		t.Fatalf("stderr should mention provider mismatch: %s", stderr.String())
	}
}

func TestRun_MinItems_FailsValidation(t *testing.T) {
	path := writeVerifyCorpus(t, t.TempDir(), nil)
	var stdout, stderr bytes.Buffer
	code := run([]string{"--corpus", path, "--min-items", "3"}, &stdout, &stderr)
	if code != exitValidation {
		t.Fatalf("exit = %d, want %d", code, exitValidation)
	}
	if !strings.Contains(stderr.String(), "items") {
		t.Fatalf("stderr should mention items: %s", stderr.String())
	}
}

func TestRun_RequiredCategory_FailsValidation(t *testing.T) {
	path := writeVerifyCorpus(t, t.TempDir(), nil)
	var stdout, stderr bytes.Buffer
	code := run([]string{"--corpus", path, "--require-category", "data_exfiltration"}, &stdout, &stderr)
	if code != exitValidation {
		t.Fatalf("exit = %d, want %d", code, exitValidation)
	}
	if !strings.Contains(stderr.String(), "data_exfiltration") {
		t.Fatalf("stderr should mention category: %s", stderr.String())
	}
}

func TestRun_InvalidCorpus_FailsValidation(t *testing.T) {
	path := writeVerifyCorpus(t, t.TempDir(), map[string]any{"normalized": false})
	var stdout, stderr bytes.Buffer
	code := run([]string{"--corpus", path}, &stdout, &stderr)
	if code != exitValidation {
		t.Fatalf("exit = %d, want %d", code, exitValidation)
	}
	if !strings.Contains(stderr.String(), "normalized") {
		t.Fatalf("stderr should mention normalized: %s", stderr.String())
	}
}

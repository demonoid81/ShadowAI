package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestRun_MissingRetention — без --retention-days → exit 1 с ошибкой.
func TestRun_MissingRetention(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--database-url", "postgres://x"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "retention-days") {
		t.Errorf("stderr должен упомянуть retention-days: %s", stderr.String())
	}
}

// TestRun_ZeroRetention — --retention-days=0 → exit 1.
func TestRun_ZeroRetention(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--retention-days", "0", "--database-url", "x"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

// TestRun_NegativeChunk — --chunk-size<=0 → exit 1.
func TestRun_NegativeChunk(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--retention-days", "30",
		"--chunk-size", "0",
		"--database-url", "x",
	}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "chunk-size") {
		t.Errorf("stderr должен упомянуть chunk-size: %s", stderr.String())
	}
}

// TestRun_MissingDBURL — без DATABASE_URL и без --database-url → exit 1.
func TestRun_MissingDBURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	var stdout, stderr bytes.Buffer
	code := run([]string{"--retention-days", "30"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "DATABASE_URL") {
		t.Errorf("stderr должен упомянуть DATABASE_URL: %s", stderr.String())
	}
}

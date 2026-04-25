//go:build enterprise

package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestRun_MissingScope — без --org-id/--all-orgs → exit 2 (PR-T2.4 fail-fast).
func TestRun_MissingScope(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--retention-days", "30", "--database-url", "x"}, &stdout, &stderr)
	if code != exitCfg {
		t.Errorf("exit = %d, want %d (exitCfg)", code, exitCfg)
	}
	if !strings.Contains(stderr.String(), "org-id") {
		t.Errorf("stderr должен упомянуть org-id: %s", stderr.String())
	}
}

// TestRun_ConflictingScope — --org-id + --all-orgs → exit 2.
func TestRun_ConflictingScope(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--retention-days", "30", "--org-id", "abc", "--all-orgs", "--database-url", "x"}, &stdout, &stderr)
	if code != exitCfg {
		t.Errorf("exit = %d, want %d (exitCfg)", code, exitCfg)
	}
}

// TestRun_MissingRetention — без --retention-days → exit 2 с ошибкой.
func TestRun_MissingRetention(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--all-orgs", "--database-url", "postgres://x"}, &stdout, &stderr)
	if code != exitCfg {
		t.Errorf("exit = %d, want %d (exitCfg)", code, exitCfg)
	}
	if !strings.Contains(stderr.String(), "retention-days") {
		t.Errorf("stderr должен упомянуть retention-days: %s", stderr.String())
	}
}

// TestRun_ZeroRetention — --retention-days=0 → exit 2.
func TestRun_ZeroRetention(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--retention-days", "0", "--all-orgs", "--database-url", "x"}, &stdout, &stderr)
	if code != exitCfg {
		t.Errorf("exit = %d, want %d (exitCfg)", code, exitCfg)
	}
}

// TestRun_NegativeChunk — --chunk-size<=0 → exit 2.
func TestRun_NegativeChunk(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--retention-days", "30",
		"--all-orgs",
		"--chunk-size", "0",
		"--database-url", "x",
	}, &stdout, &stderr)
	if code != exitCfg {
		t.Errorf("exit = %d, want %d (exitCfg)", code, exitCfg)
	}
	if !strings.Contains(stderr.String(), "chunk-size") {
		t.Errorf("stderr должен упомянуть chunk-size: %s", stderr.String())
	}
}

// TestRun_MissingDBURL — без DATABASE_URL и без --database-url → exit 2.
func TestRun_MissingDBURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	var stdout, stderr bytes.Buffer
	code := run([]string{"--retention-days", "30", "--all-orgs"}, &stdout, &stderr)
	if code != exitCfg {
		t.Errorf("exit = %d, want %d (exitCfg)", code, exitCfg)
	}
	if !strings.Contains(stderr.String(), "DATABASE_URL") {
		t.Errorf("stderr должен упомянуть DATABASE_URL: %s", stderr.String())
	}
}

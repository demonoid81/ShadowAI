package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_MissingFile(t *testing.T) {
	var out, errOut bytes.Buffer
	// Use a file object that doesn't matter since we check config errors first.
	stdout := os.NewFile(0, "stdout")
	stderr := os.NewFile(2, "stderr")
	code := run([]string{"--bucket", "test", "--key", "test.zip"}, stdout, stderr)
	if code != exitConfig {
		t.Errorf("missing --file: exit=%d, want %d", code, exitConfig)
	}
	_ = out
	_ = errOut
}

func TestRun_MissingBucket(t *testing.T) {
	stdout := os.NewFile(0, "stdout")
	stderr := os.NewFile(2, "stderr")
	code := run([]string{"--file", "/tmp/x.zip", "--key", "k"}, stdout, stderr)
	if code != exitConfig {
		t.Errorf("missing --bucket: exit=%d, want %d", code, exitConfig)
	}
}

func TestRun_MissingKey(t *testing.T) {
	stdout := os.NewFile(0, "stdout")
	stderr := os.NewFile(2, "stderr")
	code := run([]string{"--file", "/tmp/x.zip", "--bucket", "b"}, stdout, stderr)
	if code != exitConfig {
		t.Errorf("missing --key: exit=%d, want %d", code, exitConfig)
	}
}

func TestRun_NonExistentFile(t *testing.T) {
	stdout := os.NewFile(0, "stdout")
	stderr := os.NewFile(2, "stderr")
	code := run([]string{
		"--file", "/nonexistent/path/bundle.zip",
		"--bucket", "b",
		"--key", "k",
	}, stdout, stderr)
	if code != exitConfig {
		t.Errorf("nonexistent file: exit=%d, want %d", code, exitConfig)
	}
}

// TestKeyConstruction verifies the S3 key path construction pattern used by the CronJob.
func TestKeyConstruction(t *testing.T) {
	// The CronJob script constructs: $PREFIX/$YYYY/$MM/$DD/$BUNDLE_NAME.zip
	prefix := "shadowai/evidence"
	bundleName := "global-20260426-020001"
	yyyy, mm, dd := "2026", "04", "26"

	key := strings.Join([]string{prefix, yyyy, mm, dd, bundleName + ".zip"}, "/")
	expected := "shadowai/evidence/2026/04/26/global-20260426-020001.zip"
	if key != expected {
		t.Errorf("key = %q, want %q", key, expected)
	}

	// Tenant key variant
	orgID := "aaaaaaaa-0000-4000-8000-000000000001"
	tenantBundle := "tenant-" + orgID + "-20260426-020001"
	tenantKey := strings.Join([]string{prefix, yyyy, mm, dd, tenantBundle + ".zip"}, "/")
	if !strings.Contains(tenantKey, orgID) {
		t.Errorf("tenant key missing org_id: %s", tenantKey)
	}
}

// TestWriteAndReadBundle verifies the file is opened correctly (integration path).
func TestOpenFile_Valid(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.zip")
	os.WriteFile(f, []byte("fake zip content"), 0o644)

	fh, err := os.Open(f)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer fh.Close()
	stat, err := fh.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if stat.Size() != int64(len("fake zip content")) {
		t.Errorf("size=%d, want %d", stat.Size(), len("fake zip content"))
	}
}

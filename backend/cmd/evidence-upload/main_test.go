package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestRun_InvalidSSE(t *testing.T) {
	stdout := os.NewFile(0, "stdout")
	stderr := os.NewFile(2, "stderr")
	code := run([]string{"--file", "/tmp/x.zip", "--bucket", "b", "--key", "k", "--sse", "bad-value"}, stdout, stderr)
	if code != exitConfig {
		t.Errorf("invalid --sse: exit=%d, want %d", code, exitConfig)
	}
}

func TestRun_SSENone_ValidConfig(t *testing.T) {
	// sse=none is valid (for MinIO) — should pass flag validation; fails at file-not-found
	stdout := os.NewFile(0, "stdout")
	stderr := os.NewFile(2, "stderr")
	code := run([]string{"--file", "/nonexistent-bundle.zip", "--bucket", "b", "--key", "k", "--sse", "none"}, stdout, stderr)
	if code != exitConfig {
		t.Errorf("sse=none, missing file: exit=%d, want exitConfig(%d)", code, exitConfig)
	}
}

// ---------------------------------------------------------------------------
// O4.3: Object Lock flag validation
// ---------------------------------------------------------------------------

func TestRun_ObjectLock_ModeWithoutRetainUntil(t *testing.T) {
	stdout := os.NewFile(0, "stdout")
	stderr := os.NewFile(2, "stderr")
	code := run([]string{
		"--file", "/tmp/x.zip", "--bucket", "b", "--key", "k",
		"--object-lock-mode", "COMPLIANCE",
		// --retain-until missing
	}, stdout, stderr)
	if code != exitConfig {
		t.Errorf("mode without retain-until: exit=%d, want exitConfig(%d)", code, exitConfig)
	}
}

func TestRun_ObjectLock_RetainUntilWithoutMode(t *testing.T) {
	stdout := os.NewFile(0, "stdout")
	stderr := os.NewFile(2, "stderr")
	code := run([]string{
		"--file", "/tmp/x.zip", "--bucket", "b", "--key", "k",
		"--retain-until", "90d",
		// --object-lock-mode missing
	}, stdout, stderr)
	if code != exitConfig {
		t.Errorf("retain-until without mode: exit=%d, want exitConfig(%d)", code, exitConfig)
	}
}

func TestRun_ObjectLock_InvalidMode(t *testing.T) {
	stdout := os.NewFile(0, "stdout")
	stderr := os.NewFile(2, "stderr")
	code := run([]string{
		"--file", "/tmp/x.zip", "--bucket", "b", "--key", "k",
		"--object-lock-mode", "INVALID",
		"--retain-until", "90d",
	}, stdout, stderr)
	if code != exitConfig {
		t.Errorf("invalid mode: exit=%d, want exitConfig(%d)", code, exitConfig)
	}
}

func TestRun_ObjectLock_InvalidRetainUntil(t *testing.T) {
	stdout := os.NewFile(0, "stdout")
	stderr := os.NewFile(2, "stderr")
	code := run([]string{
		"--file", "/tmp/x.zip", "--bucket", "b", "--key", "k",
		"--object-lock-mode", "COMPLIANCE",
		"--retain-until", "not-a-date",
	}, stdout, stderr)
	if code != exitConfig {
		t.Errorf("invalid retain-until: exit=%d, want exitConfig(%d)", code, exitConfig)
	}
}

func TestRun_ObjectLock_RetainUntilInPast(t *testing.T) {
	stdout := os.NewFile(0, "stdout")
	stderr := os.NewFile(2, "stderr")
	code := run([]string{
		"--file", "/tmp/x.zip", "--bucket", "b", "--key", "k",
		"--object-lock-mode", "COMPLIANCE",
		"--retain-until", "2020-01-01T00:00:00Z",
	}, stdout, stderr)
	if code != exitConfig {
		t.Errorf("past retain-until: exit=%d, want exitConfig(%d)", code, exitConfig)
	}
}

func TestRun_LegalHold_InvalidValue(t *testing.T) {
	stdout := os.NewFile(0, "stdout")
	stderr := os.NewFile(2, "stderr")
	code := run([]string{
		"--file", "/tmp/x.zip", "--bucket", "b", "--key", "k",
		"--legal-hold", "MAYBE",
	}, stdout, stderr)
	if code != exitConfig {
		t.Errorf("invalid legal-hold: exit=%d, want exitConfig(%d)", code, exitConfig)
	}
}

func TestRun_ObjectLock_ValidConfig_GoesToFileError(t *testing.T) {
	// Valid Object Lock config passes flag validation; fails at missing file (still exitConfig).
	stdout := os.NewFile(0, "stdout")
	stderr := os.NewFile(2, "stderr")
	code := run([]string{
		"--file", "/nonexistent.zip", "--bucket", "b", "--key", "k",
		"--object-lock-mode", "COMPLIANCE",
		"--retain-until", "90d",
	}, stdout, stderr)
	if code != exitConfig {
		t.Errorf("valid lock config, missing file: exit=%d, want exitConfig(%d)", code, exitConfig)
	}
}

// ---------------------------------------------------------------------------
// O4.3: parseRetainUntil helper
// ---------------------------------------------------------------------------

func TestParseRetainUntil_RFC3339(t *testing.T) {
	want := "2099-06-01T12:00:00Z"
	got, err := parseRetainUntil(want)
	if err != nil {
		t.Fatalf("parseRetainUntil: %v", err)
	}
	if got.Format(time.RFC3339) != want {
		t.Errorf("got %s, want %s", got.Format(time.RFC3339), want)
	}
}

func TestParseRetainUntil_Days(t *testing.T) {
	before := time.Now().UTC()
	got, err := parseRetainUntil("90d")
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("parseRetainUntil 90d: %v", err)
	}
	low := before.Add(89 * 24 * time.Hour)
	high := after.Add(91 * 24 * time.Hour)
	if got.Before(low) || got.After(high) {
		t.Errorf("90d: got %s, want between %s and %s", got, low, high)
	}
}

func TestParseRetainUntil_Hours(t *testing.T) {
	before := time.Now().UTC()
	got, err := parseRetainUntil("8760h")
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("parseRetainUntil 8760h: %v", err)
	}
	low := before.Add(8759 * time.Hour)
	high := after.Add(8761 * time.Hour)
	if got.Before(low) || got.After(high) {
		t.Errorf("8760h: got %s, out of expected range", got)
	}
}

func TestParseRetainUntil_Invalid(t *testing.T) {
	for _, bad := range []string{"not-a-date", "0d", "-1d", ""} {
		_, err := parseRetainUntil(bad)
		if err == nil {
			t.Errorf("parseRetainUntil(%q): expected error, got nil", bad)
		}
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

//go:build integration

// O4.2.1: Integration tests for evidence-upload using a httptest fake S3 endpoint.
//
// Why httptest (not testcontainer MinIO):
//   - No Docker dependency → stable in all CI environments.
//   - Tests the actual AWS SDK request shape: URL, method, headers, body.
//   - Fast (< 100ms per test).
//   - Fake S3 ignores SigV4 signatures — focuses on upload correctness, not auth.
//
// Run:
//   go test -tags integration ./cmd/evidence-upload/... -v
package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeS3 is a minimal httptest fake S3-compatible server.
// It captures the last request for assertion and can be configured to return
// a specific HTTP status code.
type fakeS3 struct {
	statusCode  int
	lastMethod  string
	lastPath    string
	lastBody    []byte
	lastHeaders http.Header
}

// handler accepts any PUT request and returns the configured status.
// It captures request metadata for test assertions.
func (f *fakeS3) handler(w http.ResponseWriter, r *http.Request) {
	f.lastMethod = r.Method
	f.lastPath = r.URL.Path
	f.lastHeaders = r.Header.Clone()

	body, _ := io.ReadAll(r.Body)
	f.lastBody = body

	if f.statusCode == 0 {
		f.statusCode = http.StatusOK
	}
	if f.statusCode != http.StatusOK {
		// Return minimal S3 error XML so the AWS SDK parses it.
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(f.statusCode)
		fmt.Fprintf(w, `<?xml version="1.0"?>
<Error><Code>InternalError</Code>
<Message>fake S3 forced error</Message>
<RequestId>fake-req</RequestId>
</Error>`)
		return
	}

	// Minimal S3 PutObject 200 response — ETag is optional but the SDK may inspect it.
	w.Header().Set("ETag", `"fakeetag123"`)
	w.Header().Set("x-amz-request-id", "fake-request-id")
	w.WriteHeader(http.StatusOK)
}

// newFakeS3 creates a fake S3 httptest server and returns the server + state tracker.
func newFakeS3(statusCode int) (*httptest.Server, *fakeS3) {
	fs := &fakeS3{statusCode: statusCode}
	srv := httptest.NewServer(http.HandlerFunc(fs.handler))
	return srv, fs
}

// setFakeCredentials sets env vars so the AWS SDK uses static credentials
// instead of trying to reach EC2 metadata service (which times out in tests).
func setFakeCredentials(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key-id")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-access-key")
	t.Setenv("AWS_SESSION_TOKEN", "")
	// Disable AWS SDK credential chain from contacting EC2 metadata.
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

// writeTempBundle creates a small temp zip file and returns its path.
func writeTempBundle(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "bundle-*.zip")
	if err != nil {
		t.Fatalf("create temp bundle: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp bundle: %v", err)
	}
	return f.Name()
}

// setupTest sets fake AWS credentials and returns a started fake S3 server.
// Must be called at the start of every integration test to prevent AWS SDK
// credential chain from reaching EC2 metadata service (times out in CI).
func setupTest(t *testing.T, s3Status int) (*httptest.Server, *fakeS3) {
	t.Helper()
	setFakeCredentials(t)
	srv, state := newFakeS3(s3Status)
	t.Cleanup(srv.Close)
	return srv, state
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestIntegration_PutObject_PathStyle verifies that --force-path-style sends
// a PUT to /<bucket>/<key> on the custom endpoint.
func TestIntegration_PutObject_PathStyle(t *testing.T) {
	srv, state := setupTest(t, http.StatusOK)

	bundlePath := writeTempBundle(t, "fake-zip-content")

	code := run([]string{
		"--file", bundlePath,
		"--bucket", "test-bucket",
		"--key", "shadowai/evidence/2026/04/26/global-20260426.zip",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--region", "us-east-1",
		"--sse", "AES256",
		"--timeout", "30",
	}, os.Stdout, os.Stderr)
	if code != exitOK {
		t.Fatalf("expected exitOK, got %d", code)
	}

	// Verify HTTP method is PUT.
	if state.lastMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", state.lastMethod)
	}

	// Verify path-style URL: /<bucket>/<key>
	expectedPrefix := "/test-bucket/shadowai/evidence/"
	if !strings.HasPrefix(state.lastPath, expectedPrefix) {
		t.Errorf("path = %q, want prefix %q", state.lastPath, expectedPrefix)
	}

	// Verify body equals file content.
	if !bytes.Equal(state.lastBody, []byte("fake-zip-content")) {
		t.Errorf("body = %q, want %q", state.lastBody, "fake-zip-content")
	}

	t.Logf("integration/evidence-upload: PUT %s OK (body=%d bytes)", state.lastPath, len(state.lastBody))
}

// TestIntegration_SSE_AES256_Header verifies that --sse AES256 sends
// x-amz-server-side-encryption: AES256 header.
func TestIntegration_SSE_AES256_Header(t *testing.T) {
	srv, state := setupTest(t, http.StatusOK)

	bundlePath := writeTempBundle(t, "bundle-data")
	run([]string{
		"--file", bundlePath,
		"--bucket", "b",
		"--key", "k.zip",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--sse", "AES256",
		"--timeout", "30",
	}, os.Stdout, os.Stderr)

	sseHeader := state.lastHeaders.Get("x-amz-server-side-encryption")
	if sseHeader != "AES256" {
		t.Errorf("x-amz-server-side-encryption = %q, want AES256", sseHeader)
	}
	t.Logf("integration/evidence-upload: SSE=AES256 header verified")
}

// TestIntegration_SSE_None_NoHeader verifies that --sse none does NOT send
// the x-amz-server-side-encryption header (required for MinIO compatibility).
func TestIntegration_SSE_None_NoHeader(t *testing.T) {
	srv, state := setupTest(t, http.StatusOK)

	bundlePath := writeTempBundle(t, "bundle-data")
	run([]string{
		"--file", bundlePath,
		"--bucket", "b",
		"--key", "k.zip",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--sse", "none",
		"--timeout", "30",
	}, os.Stdout, os.Stderr)

	if sseHeader := state.lastHeaders.Get("x-amz-server-side-encryption"); sseHeader != "" {
		t.Errorf("sse=none: x-amz-server-side-encryption should be absent, got %q", sseHeader)
	}
	t.Logf("integration/evidence-upload: SSE=none — header correctly absent (MinIO-safe)")
}

// TestIntegration_BodyIntegrity verifies that the bytes received by S3 equal
// the input file exactly — no truncation, no corruption.
func TestIntegration_BodyIntegrity(t *testing.T) {
	srv, state := setupTest(t, http.StatusOK)

	// Use a multi-line payload to catch framing issues.
	content := strings.Repeat("evidence-bundle-byte\n", 500) // ~10KB
	bundlePath := writeTempBundle(t, content)

	code := run([]string{
		"--file", bundlePath,
		"--bucket", "b",
		"--key", "k.zip",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--sse", "AES256",
		"--timeout", "30",
	}, os.Stdout, os.Stderr)
	if code != exitOK {
		t.Fatalf("expected exitOK, got %d", code)
	}

	if !bytes.Equal(state.lastBody, []byte(content)) {
		t.Errorf("body integrity failure: received %d bytes, want %d", len(state.lastBody), len(content))
	}
	t.Logf("integration/evidence-upload: body integrity OK (%d bytes)", len(state.lastBody))
}

// TestIntegration_BucketAndKeyInPath verifies the S3 path encodes bucket and key correctly.
func TestIntegration_BucketAndKeyInPath(t *testing.T) {
	srv, state := setupTest(t, http.StatusOK)

	bundlePath := writeTempBundle(t, "x")
	run([]string{
		"--file", bundlePath,
		"--bucket", "shadowai-compliance",
		"--key", "shadowai/evidence/2026/04/26/tenant-org1-20260426.zip",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--sse", "none",
		"--timeout", "30",
	}, os.Stdout, os.Stderr)

	if !strings.Contains(state.lastPath, "shadowai-compliance") {
		t.Errorf("path missing bucket: %s", state.lastPath)
	}
	if !strings.Contains(state.lastPath, "tenant-org1") {
		t.Errorf("path missing key component: %s", state.lastPath)
	}
	t.Logf("integration/evidence-upload: path=%s", state.lastPath)
}

// TestIntegration_UploadFailure_500 verifies that an S3 5xx response causes exit 1.
func TestIntegration_UploadFailure_500(t *testing.T) {
	srv, _ := setupTest(t, http.StatusInternalServerError)

	bundlePath := writeTempBundle(t, "bundle")
	code := run([]string{
		"--file", bundlePath,
		"--bucket", "b",
		"--key", "k.zip",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--sse", "none",
		"--timeout", "30",
	}, os.Stdout, os.Stderr)
	if code != exitFail {
		t.Errorf("S3 500: exit=%d, want exitFail(%d)", code, exitFail)
	}
	t.Logf("integration/evidence-upload: S3 500 → exit 1 (upload failure) ✓")
}

// TestIntegration_ContentType verifies Content-Type is application/zip.
func TestIntegration_ContentType(t *testing.T) {
	srv, state := setupTest(t, http.StatusOK)

	bundlePath := writeTempBundle(t, "zip")
	run([]string{
		"--file", bundlePath,
		"--bucket", "b",
		"--key", "k.zip",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--sse", "none",
		"--timeout", "30",
	}, os.Stdout, os.Stderr)

	ct := state.lastHeaders.Get("Content-Type")
	if ct != "application/zip" {
		t.Errorf("Content-Type = %q, want application/zip", ct)
	}
}

// TestIntegration_ShadowaiMetadataHeader verifies the x-amz-meta-* headers
// (shadowai-component and upload-timestamp) are sent.
func TestIntegration_ShadowaiMetadataHeader(t *testing.T) {
	srv, state := setupTest(t, http.StatusOK)

	bundlePath := writeTempBundle(t, "x")
	run([]string{
		"--file", bundlePath,
		"--bucket", "b",
		"--key", "k.zip",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--sse", "none",
		"--timeout", "30",
	}, os.Stdout, os.Stderr)

	comp := state.lastHeaders.Get("x-amz-meta-shadowai-component")
	if comp != "evidence-bundle" {
		t.Errorf("x-amz-meta-shadowai-component = %q, want evidence-bundle", comp)
	}
	ts := state.lastHeaders.Get("x-amz-meta-upload-timestamp")
	if ts == "" {
		t.Error("x-amz-meta-upload-timestamp missing")
	}
	t.Logf("integration/evidence-upload: metadata headers OK (component=%s ts=%s)", comp, ts[:10])
}

// TestIntegration_ConfigError_MissingFile ensures config errors still return 2
// (not 1) — regression guard after adding integration infrastructure.
func TestIntegration_ConfigError_MissingFile(t *testing.T) {
	srv, _ := setupTest(t, http.StatusOK)

	code := run([]string{
		"--bucket", "b",
		"--key", "k.zip",
		"--endpoint", srv.URL,
	}, os.Stdout, os.Stderr)
	if code != exitConfig {
		t.Errorf("missing --file: exit=%d, want exitConfig(%d)", code, exitConfig)
	}
}

// ---------------------------------------------------------------------------
// Key construction helper (not AWS-specific, tested here for completeness)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// O4.3: Object Lock integration tests
// ---------------------------------------------------------------------------

// TestIntegration_ObjectLock_COMPLIANCE_Headers verifies that --object-lock-mode COMPLIANCE
// and --retain-until send the correct x-amz-object-lock-* headers.
func TestIntegration_ObjectLock_COMPLIANCE_Headers(t *testing.T) {
	srv, state := setupTest(t, http.StatusOK)

	bundlePath := writeTempBundle(t, "compliance-bundle")
	retainDate := "2099-06-01T00:00:00Z"

	code := run([]string{
		"--file", bundlePath,
		"--bucket", "b",
		"--key", "k.zip",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--sse", "none",
		"--timeout", "30",
		"--object-lock-mode", "COMPLIANCE",
		"--retain-until", retainDate,
	}, os.Stdout, os.Stderr)
	if code != exitOK {
		t.Fatalf("expected exitOK, got %d", code)
	}

	mode := state.lastHeaders.Get("x-amz-object-lock-mode")
	if mode != "COMPLIANCE" {
		t.Errorf("x-amz-object-lock-mode = %q, want COMPLIANCE", mode)
	}
	retain := state.lastHeaders.Get("x-amz-object-lock-retain-until-date")
	if retain == "" {
		t.Error("x-amz-object-lock-retain-until-date missing")
	}
	if !strings.Contains(retain, "2099") {
		t.Errorf("x-amz-object-lock-retain-until-date = %q, want year 2099", retain)
	}
	t.Logf("integration/o4.3: COMPLIANCE mode=%s retain=%s", mode, retain)
}

// TestIntegration_ObjectLock_GOVERNANCE_Headers verifies GOVERNANCE mode header.
func TestIntegration_ObjectLock_GOVERNANCE_Headers(t *testing.T) {
	srv, state := setupTest(t, http.StatusOK)

	bundlePath := writeTempBundle(t, "governance-bundle")

	run([]string{
		"--file", bundlePath,
		"--bucket", "b",
		"--key", "k.zip",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--sse", "none",
		"--timeout", "30",
		"--object-lock-mode", "GOVERNANCE",
		"--retain-until", "90d",
	}, os.Stdout, os.Stderr)

	mode := state.lastHeaders.Get("x-amz-object-lock-mode")
	if mode != "GOVERNANCE" {
		t.Errorf("x-amz-object-lock-mode = %q, want GOVERNANCE", mode)
	}
	retain := state.lastHeaders.Get("x-amz-object-lock-retain-until-date")
	if retain == "" {
		t.Error("x-amz-object-lock-retain-until-date missing for 90d retention")
	}
	t.Logf("integration/o4.3: GOVERNANCE mode=%s retain=%s", mode, retain)
}

// TestIntegration_ObjectLock_LegalHold_ON verifies --legal-hold ON sends the header.
func TestIntegration_ObjectLock_LegalHold_ON(t *testing.T) {
	srv, state := setupTest(t, http.StatusOK)

	bundlePath := writeTempBundle(t, "hold-bundle")

	run([]string{
		"--file", bundlePath,
		"--bucket", "b",
		"--key", "k.zip",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--sse", "none",
		"--timeout", "30",
		"--object-lock-mode", "COMPLIANCE",
		"--retain-until", "2099-12-31T00:00:00Z",
		"--legal-hold", "ON",
	}, os.Stdout, os.Stderr)

	hold := state.lastHeaders.Get("x-amz-object-lock-legal-hold")
	if hold != "ON" {
		t.Errorf("x-amz-object-lock-legal-hold = %q, want ON", hold)
	}
	t.Logf("integration/o4.3: legal-hold=%s", hold)
}

// TestIntegration_ObjectLock_ChecksumSHA256 verifies that an Object Lock upload
// sends x-amz-checksum-sha256 and x-amz-sdk-checksum-algorithm: SHA256.
// AWS S3 requires a checksum for every PutObject that sets Object Lock retention.
func TestIntegration_ObjectLock_ChecksumSHA256(t *testing.T) {
	srv, state := setupTest(t, http.StatusOK)

	bundlePath := writeTempBundle(t, "checksum-bundle-data")
	code := run([]string{
		"--file", bundlePath,
		"--bucket", "b",
		"--key", "k.zip",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--sse", "none",
		"--timeout", "30",
		"--object-lock-mode", "COMPLIANCE",
		"--retain-until", "2099-12-31T00:00:00Z",
	}, os.Stdout, os.Stderr)
	if code != exitOK {
		t.Fatalf("expected exitOK, got %d", code)
	}

	checksum := state.lastHeaders.Get("x-amz-checksum-sha256")
	if checksum == "" {
		t.Error("x-amz-checksum-sha256 missing — AWS S3 will reject Object Lock uploads without it")
	}
	algo := state.lastHeaders.Get("x-amz-sdk-checksum-algorithm")
	if algo != "SHA256" {
		t.Errorf("x-amz-sdk-checksum-algorithm = %q, want SHA256", algo)
	}
	t.Logf("integration/o4.3: checksum sha256=%s (len=%d) algo=%s", checksum[:8]+"…", len(checksum), algo)
}

// TestIntegration_ObjectLock_NoFlags_NoChecksumHeader — plain upload (no Object Lock)
// must NOT send the checksum headers (overhead + MinIO compatibility concern).
func TestIntegration_ObjectLock_NoChecksumOnPlainUpload(t *testing.T) {
	srv, state := setupTest(t, http.StatusOK)

	bundlePath := writeTempBundle(t, "plain-no-checksum")
	run([]string{
		"--file", bundlePath,
		"--bucket", "b",
		"--key", "k.zip",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--sse", "AES256",
		"--timeout", "30",
		// No --object-lock-mode
	}, os.Stdout, os.Stderr)

	if v := state.lastHeaders.Get("x-amz-checksum-sha256"); v != "" {
		t.Errorf("plain upload should not send x-amz-checksum-sha256, got %q", v)
	}
	if v := state.lastHeaders.Get("x-amz-sdk-checksum-algorithm"); v != "" {
		t.Errorf("plain upload should not send x-amz-sdk-checksum-algorithm, got %q", v)
	}
	t.Logf("integration/o4.3: no checksum headers on plain upload ✓")
}

// TestIntegration_ObjectLock_NoFlags_NoHeaders is a regression guard: without
// --object-lock-mode, none of the x-amz-object-lock-* headers must appear.
func TestIntegration_ObjectLock_NoFlags_NoHeaders(t *testing.T) {
	srv, state := setupTest(t, http.StatusOK)

	bundlePath := writeTempBundle(t, "plain-bundle")
	run([]string{
		"--file", bundlePath,
		"--bucket", "b",
		"--key", "k.zip",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--sse", "AES256",
		"--timeout", "30",
	}, os.Stdout, os.Stderr)

	for _, h := range []string{
		"x-amz-object-lock-mode",
		"x-amz-object-lock-retain-until-date",
		"x-amz-object-lock-legal-hold",
	} {
		if v := state.lastHeaders.Get(h); v != "" {
			t.Errorf("no-lock upload: header %s should be absent, got %q", h, v)
		}
	}
	t.Logf("integration/o4.3: no Object Lock headers on plain upload ✓")
}

// ---------------------------------------------------------------------------
// Key construction helper (not AWS-specific, tested here for completeness)
// ---------------------------------------------------------------------------

func TestIntegration_S3KeyFormat(t *testing.T) {
	prefix := "shadowai/evidence"
	cases := []struct {
		yyyy, mm, dd, bundle, want string
	}{
		{"2026", "04", "26", "global-20260426-020000",
			"shadowai/evidence/2026/04/26/global-20260426-020000.zip"},
		{"2026", "04", "26", "tenant-aaaaaaaa-0000-4000-8000-000000000001-20260426-020000",
			"shadowai/evidence/2026/04/26/tenant-aaaaaaaa-0000-4000-8000-000000000001-20260426-020000.zip"},
	}
	for _, tc := range cases {
		key := filepath.Join(prefix, tc.yyyy, tc.mm, tc.dd, tc.bundle+".zip")
		// filepath.Join uses OS separator; normalize to forward slashes for S3
		key = strings.ReplaceAll(key, string(os.PathSeparator), "/")
		if key != tc.want {
			t.Errorf("key = %q, want %q", key, tc.want)
		}
	}
}

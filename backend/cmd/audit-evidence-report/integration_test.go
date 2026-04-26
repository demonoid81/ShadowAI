//go:build integration

// PR-O4.4: Integration tests for audit-evidence-report using httptest fake S3.
//
// The fakeS3Reporter serves three request types:
//   - GET  /<bucket>?list-type=2  → ListObjectsV2 XML
//   - HEAD /<bucket>/<key>        → Object Lock headers
//   - GET  /<bucket>/<key>        → object body (for --read-manifest)
//
// All tests use path-style addressing and fake credentials to avoid network
// timeouts against EC2 metadata service.
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fake S3 server
// ---------------------------------------------------------------------------

// s3Object is one pre-configured object in fakeS3Reporter.
type s3Object struct {
	key          string
	size         int64
	etag         string
	lastModified time.Time
	lockMode     string // "COMPLIANCE" | "GOVERNANCE" | ""
	retainUntil  *time.Time
	legalHold    string     // "ON" | "OFF" | ""
	content      []byte     // body returned by GET (nil = empty)
}

// fakeS3Reporter is a minimal httptest S3 server for the audit report tool.
type fakeS3Reporter struct {
	objects []s3Object
}

func (f *fakeS3Reporter) handler(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
		f.handleList(w, r)
	case r.Method == http.MethodHead:
		f.handleHead(w, r)
	case r.Method == http.MethodGet:
		f.handleGet(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// listBucketResult is the XML shape for ListObjectsV2.
type listBucketResult struct {
	XMLName     xml.Name        `xml:"ListBucketResult"`
	XMLNS       string          `xml:"xmlns,attr"`
	Name        string          `xml:"Name"`
	Prefix      string          `xml:"Prefix"`
	KeyCount    int             `xml:"KeyCount"`
	MaxKeys     int             `xml:"MaxKeys"`
	IsTruncated bool            `xml:"IsTruncated"`
	Contents    []listContents  `xml:"Contents"`
}

type listContents struct {
	Key          string `xml:"Key"`
	Size         int64  `xml:"Size"`
	ETag         string `xml:"ETag"`
	LastModified string `xml:"LastModified"` // ISO8601
	StorageClass string `xml:"StorageClass"`
}

func (f *fakeS3Reporter) handleList(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	var contents []listContents
	for _, obj := range f.objects {
		if prefix != "" && !strings.HasPrefix(obj.key, prefix) {
			continue
		}
		contents = append(contents, listContents{
			Key:          obj.key,
			Size:         obj.size,
			ETag:         `"` + obj.etag + `"`,
			LastModified: obj.lastModified.UTC().Format("2006-01-02T15:04:05.000Z"),
			StorageClass: "STANDARD",
		})
	}
	result := listBucketResult{
		XMLNS:       "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:        "test-bucket",
		Prefix:      prefix,
		KeyCount:    len(contents),
		MaxKeys:     1000,
		IsTruncated: false,
		Contents:    contents,
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	enc := xml.NewEncoder(w)
	enc.Encode(result) //nolint:errcheck
}

func (f *fakeS3Reporter) findObject(r *http.Request) *s3Object {
	// Strip leading "/<bucket>/" to get the key.
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) < 2 {
		return nil
	}
	key := parts[1]
	for i := range f.objects {
		if f.objects[i].key == key {
			return &f.objects[i]
		}
	}
	return nil
}

func (f *fakeS3Reporter) handleHead(w http.ResponseWriter, r *http.Request) {
	obj := f.findObject(r)
	if obj == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	f.setObjectHeaders(w, obj)
	w.WriteHeader(http.StatusOK)
}

func (f *fakeS3Reporter) handleGet(w http.ResponseWriter, r *http.Request) {
	obj := f.findObject(r)
	if obj == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	f.setObjectHeaders(w, obj)
	w.WriteHeader(http.StatusOK)
	if obj.content != nil {
		w.Write(obj.content) //nolint:errcheck
	}
}

func (f *fakeS3Reporter) setObjectHeaders(w http.ResponseWriter, obj *s3Object) {
	w.Header().Set("Content-Length", fmt.Sprintf("%d", obj.size))
	w.Header().Set("ETag", `"`+obj.etag+`"`)
	w.Header().Set("Last-Modified",
		obj.lastModified.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	w.Header().Set("x-amz-request-id", "fake-request-id")
	if obj.lockMode != "" {
		w.Header().Set("x-amz-object-lock-mode", obj.lockMode)
	}
	if obj.retainUntil != nil {
		w.Header().Set("x-amz-object-lock-retain-until-date",
			obj.retainUntil.UTC().Format(time.RFC3339))
	}
	if obj.legalHold != "" {
		w.Header().Set("x-amz-object-lock-legal-hold", obj.legalHold)
	}
}

func newFakeReporter(objects []s3Object) (*httptest.Server, *fakeS3Reporter) {
	fr := &fakeS3Reporter{objects: objects}
	srv := httptest.NewServer(http.HandlerFunc(fr.handler))
	return srv, fr
}

// setFakeCredentials prevents AWS SDK from hitting EC2 metadata service.
func setFakeCredentials(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "test-key-id")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

// buildManifestZip creates a valid zip containing bundle_manifest.json.
func buildManifestZip(t *testing.T, orgID string, tables []string, exportTime time.Time) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("bundle_manifest.json")
	type mf struct {
		Version    string    `json:"version"`
		ExportTime time.Time `json:"export_time"`
		Tables     []string  `json:"tables"`
		OrgID      string    `json:"org_id"`
	}
	json.NewEncoder(f).Encode(mf{ //nolint:errcheck
		Version: "1", ExportTime: exportTime, Tables: tables, OrgID: orgID,
	})
	zw.Close()
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestIntegration_Report_CompliantBundles verifies that bundles with COMPLIANCE
// Object Lock and sufficient retention are reported as compliant.
func TestIntegration_Report_CompliantBundles(t *testing.T) {
	setFakeCredentials(t)

	retain := time.Now().UTC().Add(120 * 24 * time.Hour)
	objects := []s3Object{
		{
			key:          "shadowai/evidence/2026/04/26/global-20260426-020001.zip",
			size:         12345,
			etag:         "abc123",
			lastModified: time.Date(2026, 4, 26, 2, 0, 1, 0, time.UTC),
			lockMode:     "COMPLIANCE",
			retainUntil:  &retain,
			legalHold:    "OFF",
		},
	}
	srv, _ := newFakeReporter(objects)
	defer srv.Close()

	var out, errBuf bytes.Buffer
	code := run([]string{
		"--bucket", "test-bucket",
		"--prefix", "shadowai/evidence",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--require-lock",
		"--min-retention-days", "90",
		"--format", "json",
		"--timeout", "30",
	}, &out, &errBuf)

	if code != exitOK {
		t.Fatalf("compliant bundles: exit=%d, want exitOK(%d)\nstderr: %s", code, exitOK, errBuf.String())
	}

	var report Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("parse JSON report: %v\noutput: %s", err, out.String())
	}
	if report.TotalBundles != 1 {
		t.Errorf("TotalBundles=%d, want 1", report.TotalBundles)
	}
	if report.ViolationCount != 0 {
		t.Errorf("ViolationCount=%d, want 0", report.ViolationCount)
	}
	b := report.Bundles[0]
	if b.BundleType != "global" {
		t.Errorf("BundleType=%q, want global", b.BundleType)
	}
	if b.LockMode != "COMPLIANCE" {
		t.Errorf("LockMode=%q, want COMPLIANCE", b.LockMode)
	}
	t.Logf("integration/o4.4: compliant report OK (bundles=%d violations=%d)", report.TotalBundles, report.ViolationCount)
}

// TestIntegration_Report_MissingLock_DetectsViolation verifies that a bundle
// without Object Lock is flagged when --require-lock is set.
func TestIntegration_Report_MissingLock_DetectsViolation(t *testing.T) {
	setFakeCredentials(t)

	objects := []s3Object{
		{
			key:          "shadowai/evidence/2026/04/25/global-20260425-020001.zip",
			size:         9999,
			etag:         "nolock",
			lastModified: time.Date(2026, 4, 25, 2, 0, 0, 0, time.UTC),
			// lockMode, retainUntil, legalHold intentionally empty
		},
	}
	srv, _ := newFakeReporter(objects)
	defer srv.Close()

	var out, errBuf bytes.Buffer
	code := run([]string{
		"--bucket", "test-bucket",
		"--prefix", "shadowai/evidence",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--require-lock",
		"--format", "json",
		"--timeout", "30",
	}, &out, &errBuf)

	if code != exitViolation {
		t.Fatalf("missing lock: exit=%d, want exitViolation(%d)\nstderr: %s", code, exitViolation, errBuf.String())
	}

	var report Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	if report.ViolationCount != 1 {
		t.Errorf("ViolationCount=%d, want 1", report.ViolationCount)
	}
	if report.Bundles[0].Compliant {
		t.Error("bundle with no lock should not be compliant")
	}
	viols := strings.Join(report.Bundles[0].Violations, ",")
	if !strings.Contains(viols, "missing_object_lock") {
		t.Errorf("want missing_object_lock violation, got %q", viols)
	}
	t.Logf("integration/o4.4: missing lock detected → violation ✓")
}

// TestIntegration_Report_RetentionTooShort_DetectsViolation verifies that a
// retain_until shorter than the policy minimum is flagged.
func TestIntegration_Report_RetentionTooShort_DetectsViolation(t *testing.T) {
	setFakeCredentials(t)

	// 10 days from now — below 90-day policy.
	shortRetain := time.Now().UTC().Add(10 * 24 * time.Hour)
	objects := []s3Object{
		{
			key:          "shadowai/evidence/2026/04/26/global-20260426-020001.zip",
			size:         5555,
			etag:         "short",
			lastModified: time.Date(2026, 4, 26, 2, 0, 0, 0, time.UTC),
			lockMode:     "GOVERNANCE",
			retainUntil:  &shortRetain,
		},
	}
	srv, _ := newFakeReporter(objects)
	defer srv.Close()

	var out, errBuf bytes.Buffer
	code := run([]string{
		"--bucket", "test-bucket",
		"--prefix", "shadowai/evidence",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--min-retention-days", "90",
		"--format", "json",
		"--timeout", "30",
	}, &out, &errBuf)

	if code != exitViolation {
		t.Fatalf("short retention: exit=%d, want exitViolation(%d)", code, exitViolation)
	}

	var report Report
	json.Unmarshal(out.Bytes(), &report) //nolint:errcheck
	if report.ViolationCount != 1 {
		t.Errorf("ViolationCount=%d, want 1", report.ViolationCount)
	}
	viols := strings.Join(report.Bundles[0].Violations, ",")
	if !strings.Contains(viols, "retention_too_short") {
		t.Errorf("want retention_too_short, got %q", viols)
	}
	t.Logf("integration/o4.4: short retention detected → violation ✓")
}

// TestIntegration_Report_TenantGlobalSeparation verifies that global and tenant
// bundles have correct bundle_type and org_id fields set.
func TestIntegration_Report_TenantGlobalSeparation(t *testing.T) {
	setFakeCredentials(t)

	uuid := "aaaaaaaa-0000-4000-8000-000000000001"
	retain := time.Now().UTC().Add(100 * 24 * time.Hour)
	objects := []s3Object{
		{
			key:          "shadowai/evidence/2026/04/26/global-20260426-020001.zip",
			size:         1000, etag: "g1",
			lastModified: time.Date(2026, 4, 26, 2, 0, 0, 0, time.UTC),
			lockMode: "COMPLIANCE", retainUntil: &retain,
		},
		{
			key:          "shadowai/evidence/2026/04/26/tenant-" + uuid + "-20260426-020001.zip",
			size:         800, etag: "t1",
			lastModified: time.Date(2026, 4, 26, 2, 1, 0, 0, time.UTC),
			lockMode: "COMPLIANCE", retainUntil: &retain,
		},
	}
	srv, _ := newFakeReporter(objects)
	defer srv.Close()

	var out, errBuf bytes.Buffer
	code := run([]string{
		"--bucket", "test-bucket",
		"--prefix", "shadowai/evidence",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--format", "json",
		"--timeout", "30",
	}, &out, &errBuf)

	if code != exitOK {
		t.Fatalf("exit=%d\nstderr: %s", code, errBuf.String())
	}

	var report Report
	json.Unmarshal(out.Bytes(), &report) //nolint:errcheck
	if report.TotalBundles != 2 {
		t.Fatalf("TotalBundles=%d, want 2", report.TotalBundles)
	}

	byType := map[string]BundleRecord{}
	for _, b := range report.Bundles {
		byType[b.BundleType] = b
	}
	if byType["global"].OrgID != "" {
		t.Errorf("global org_id=%q, want empty", byType["global"].OrgID)
	}
	if byType["tenant"].OrgID != uuid {
		t.Errorf("tenant org_id=%q, want %s", byType["tenant"].OrgID, uuid)
	}
	t.Logf("integration/o4.4: tenant/global separation verified ✓")
}

// TestIntegration_Report_NoPolicy_AllCompliant verifies exit 0 when no policy
// flags are set even if Object Lock is absent.
func TestIntegration_Report_NoPolicy_AllCompliant(t *testing.T) {
	setFakeCredentials(t)

	objects := []s3Object{
		{
			key:          "shadowai/evidence/2026/04/26/global-20260426-020001.zip",
			size:         100, etag: "np",
			lastModified: time.Date(2026, 4, 26, 2, 0, 0, 0, time.UTC),
			// no lock
		},
	}
	srv, _ := newFakeReporter(objects)
	defer srv.Close()

	var out, errBuf bytes.Buffer
	code := run([]string{
		"--bucket", "test-bucket",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--format", "json",
		"--timeout", "30",
		// no --require-lock, no --min-retention-days
	}, &out, &errBuf)

	if code != exitOK {
		t.Errorf("no policy: exit=%d, want exitOK", code)
	}
}

// TestIntegration_Report_ReadManifest verifies --read-manifest populates
// ManifestOrgID, ManifestTables, ManifestExportTime from bundle_manifest.json.
func TestIntegration_Report_ReadManifest(t *testing.T) {
	setFakeCredentials(t)

	exportTime := time.Date(2026, 4, 26, 2, 0, 0, 0, time.UTC)
	uuid := "bbbbbbbb-0000-4000-8000-000000000002"
	zipContent := buildManifestZip(t, uuid, []string{"audit_logs", "admin_event_logs"}, exportTime)

	retain := time.Now().UTC().Add(100 * 24 * time.Hour)
	objects := []s3Object{
		{
			key:          "shadowai/evidence/2026/04/26/tenant-" + uuid + "-20260426-020001.zip",
			size:         int64(len(zipContent)),
			etag:         "mftest",
			lastModified: time.Date(2026, 4, 26, 2, 0, 0, 0, time.UTC),
			lockMode:     "COMPLIANCE",
			retainUntil:  &retain,
			content:      zipContent,
		},
	}
	srv, _ := newFakeReporter(objects)
	defer srv.Close()

	var out, errBuf bytes.Buffer
	code := run([]string{
		"--bucket", "test-bucket",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--format", "json",
		"--read-manifest",
		"--timeout", "30",
	}, &out, &errBuf)

	if code != exitOK {
		t.Fatalf("read-manifest: exit=%d\nstderr: %s\nstdout: %s", code, errBuf.String(), out.String())
	}

	var report Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	if len(report.Bundles) != 1 {
		t.Fatalf("want 1 bundle, got %d", len(report.Bundles))
	}
	b := report.Bundles[0]
	if b.ManifestOrgID != uuid {
		t.Errorf("ManifestOrgID=%q, want %s", b.ManifestOrgID, uuid)
	}
	if len(b.ManifestTables) != 2 {
		t.Errorf("ManifestTables=%v, want [audit_logs admin_event_logs]", b.ManifestTables)
	}
	if b.ManifestExportTime == nil {
		t.Error("ManifestExportTime missing")
	}
	t.Logf("integration/o4.4: manifest org_id=%s tables=%v ✓", b.ManifestOrgID, b.ManifestTables)
}

// TestIntegration_Report_DateFilter verifies --after / --before filter by last_modified.
func TestIntegration_Report_DateFilter(t *testing.T) {
	setFakeCredentials(t)

	objects := []s3Object{
		{
			key: "shadowai/evidence/2026/03/01/global-20260301-020001.zip",
			size: 100, etag: "march",
			lastModified: time.Date(2026, 3, 1, 2, 0, 0, 0, time.UTC),
		},
		{
			key: "shadowai/evidence/2026/04/26/global-20260426-020001.zip",
			size: 200, etag: "april",
			lastModified: time.Date(2026, 4, 26, 2, 0, 0, 0, time.UTC),
		},
	}
	srv, _ := newFakeReporter(objects)
	defer srv.Close()

	var out, errBuf bytes.Buffer
	code := run([]string{
		"--bucket", "test-bucket",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--after", "2026-04-01",
		"--format", "json",
		"--timeout", "30",
	}, &out, &errBuf)

	if code != exitOK {
		t.Fatalf("date filter: exit=%d", code)
	}

	var report Report
	json.Unmarshal(out.Bytes(), &report) //nolint:errcheck
	if report.TotalBundles != 1 {
		t.Errorf("after=2026-04-01: TotalBundles=%d, want 1 (only april)", report.TotalBundles)
	}
	if !strings.Contains(report.Bundles[0].Key, "20260426") {
		t.Errorf("expected april bundle, got %s", report.Bundles[0].Key)
	}
	t.Logf("integration/o4.4: date filter --after=2026-04-01 → 1 bundle ✓")
}

// TestIntegration_Report_JSONFields verifies the JSON report contains all fields
// required for audit archive.
func TestIntegration_Report_JSONFields(t *testing.T) {
	setFakeCredentials(t)

	retain := time.Now().UTC().Add(100 * 24 * time.Hour)
	objects := []s3Object{
		{
			key: "shadowai/evidence/2026/04/26/global-20260426-020001.zip",
			size: 55000, etag: "fields",
			lastModified: time.Date(2026, 4, 26, 2, 0, 0, 0, time.UTC),
			lockMode: "COMPLIANCE", retainUntil: &retain, legalHold: "OFF",
		},
	}
	srv, _ := newFakeReporter(objects)
	defer srv.Close()

	var out bytes.Buffer
	run([]string{ //nolint:errcheck
		"--bucket", "test-bucket",
		"--endpoint", srv.URL,
		"--force-path-style",
		"--require-lock",
		"--min-retention-days", "90",
		"--format", "json",
		"--timeout", "30",
	}, &out, os.Stderr)

	raw := out.String()
	for _, field := range []string{
		"generated_at", "bucket", "prefix",
		"require_lock", "min_retention_days",
		"total_bundles", "compliant_count", "violation_count",
		"bundle_type", "org_id", "size_bytes", "etag", "last_modified",
		"lock_mode", "retain_until", "legal_hold",
		"compliant",
	} {
		if !strings.Contains(raw, field) {
			t.Errorf("JSON report missing field %q", field)
		}
	}
	t.Logf("integration/o4.4: JSON fields verified ✓")
}

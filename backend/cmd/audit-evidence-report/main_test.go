package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// parseKeyInfo
// ---------------------------------------------------------------------------

func TestParseKeyInfo_Global(t *testing.T) {
	bt, org := parseKeyInfo("shadowai/evidence/2026/04/26/global-20260426-020001.zip")
	if bt != "global" || org != "" {
		t.Errorf("global key: type=%q org=%q, want global/\"\"", bt, org)
	}
}

func TestParseKeyInfo_Tenant(t *testing.T) {
	uuid := "aaaaaaaa-0000-4000-8000-000000000001"
	bt, org := parseKeyInfo("shadowai/evidence/2026/04/26/tenant-" + uuid + "-20260426-020001.zip")
	if bt != "tenant" {
		t.Errorf("type=%q, want tenant", bt)
	}
	if org != uuid {
		t.Errorf("org=%q, want %s", org, uuid)
	}
}

func TestParseKeyInfo_Unknown(t *testing.T) {
	bt, org := parseKeyInfo("shadowai/evidence/2026/04/26/backup-20260426.zip")
	if bt != "unknown" || org != "" {
		t.Errorf("unknown key: type=%q org=%q, want unknown/\"\"", bt, org)
	}
}

// ---------------------------------------------------------------------------
// checkCompliance
// ---------------------------------------------------------------------------

func ptrTime(t time.Time) *time.Time { return &t }

func TestCheckCompliance_NoLockNoPolicy(t *testing.T) {
	rec := BundleRecord{Key: "k.zip"}
	checkCompliance(&rec, false, 0)
	if !rec.Compliant || len(rec.Violations) != 0 {
		t.Errorf("no policy: want compliant, got %v %v", rec.Compliant, rec.Violations)
	}
}

func TestCheckCompliance_MissingLock_RequireLockTrue(t *testing.T) {
	rec := BundleRecord{Key: "k.zip", LockMode: ""}
	checkCompliance(&rec, true, 0)
	if rec.Compliant {
		t.Error("missing lock with require-lock=true: want violation")
	}
	if len(rec.Violations) == 0 || !strings.Contains(rec.Violations[0], "missing_object_lock") {
		t.Errorf("want missing_object_lock violation, got %v", rec.Violations)
	}
}

func TestCheckCompliance_LockPresent_RequireLockTrue(t *testing.T) {
	future := time.Now().UTC().Add(100 * 24 * time.Hour)
	rec := BundleRecord{Key: "k.zip", LockMode: "COMPLIANCE", RetainUntil: ptrTime(future)}
	checkCompliance(&rec, true, 0)
	if !rec.Compliant {
		t.Errorf("lock present: want compliant, got violations %v", rec.Violations)
	}
}

func TestCheckCompliance_LockExpired(t *testing.T) {
	past := time.Now().UTC().Add(-24 * time.Hour)
	rec := BundleRecord{Key: "k.zip", LockMode: "COMPLIANCE", RetainUntil: ptrTime(past)}
	checkCompliance(&rec, false, 0)
	if rec.Compliant {
		t.Error("expired lock: want violation")
	}
	if len(rec.Violations) == 0 || !strings.Contains(rec.Violations[0], "lock_expired") {
		t.Errorf("want lock_expired violation, got %v", rec.Violations)
	}
}

func TestCheckCompliance_RetentionTooShort(t *testing.T) {
	// 10 days from now, but policy requires 90.
	retain := time.Now().UTC().Add(10 * 24 * time.Hour)
	rec := BundleRecord{Key: "k.zip", LockMode: "COMPLIANCE", RetainUntil: ptrTime(retain)}
	checkCompliance(&rec, false, 90)
	if rec.Compliant {
		t.Error("retention_too_short: want violation")
	}
	if len(rec.Violations) == 0 || !strings.Contains(rec.Violations[0], "retention_too_short") {
		t.Errorf("want retention_too_short violation, got %v", rec.Violations)
	}
}

func TestCheckCompliance_RetentionSufficient(t *testing.T) {
	retain := time.Now().UTC().Add(120 * 24 * time.Hour)
	rec := BundleRecord{Key: "k.zip", LockMode: "COMPLIANCE", RetainUntil: ptrTime(retain)}
	checkCompliance(&rec, true, 90)
	if !rec.Compliant {
		t.Errorf("sufficient retention: want compliant, got %v", rec.Violations)
	}
}

func TestCheckCompliance_MultipleViolations(t *testing.T) {
	// No lock + expired (if RetainUntil set in past but LockMode empty)
	past := time.Now().UTC().Add(-24 * time.Hour)
	rec := BundleRecord{Key: "k.zip", LockMode: "", RetainUntil: ptrTime(past)}
	checkCompliance(&rec, true, 90)
	if rec.Compliant {
		t.Error("want violations")
	}
	if len(rec.Violations) < 2 {
		t.Errorf("want ≥2 violations (missing_lock + expired), got %v", rec.Violations)
	}
}

// ---------------------------------------------------------------------------
// buildReport
// ---------------------------------------------------------------------------

func TestBuildReport_Summary(t *testing.T) {
	bundles := []BundleRecord{
		{Key: "a.zip", Compliant: true},
		{Key: "b.zip", Compliant: false, Violations: []string{"missing_object_lock"}},
	}
	r := buildReport("bucket", "pfx", "", "", true, 90, bundles)
	if r.TotalBundles != 2 {
		t.Errorf("TotalBundles=%d, want 2", r.TotalBundles)
	}
	if r.CompliantCount != 1 || r.ViolationCount != 1 {
		t.Errorf("compliant=%d violations=%d, want 1/1", r.CompliantCount, r.ViolationCount)
	}
}

// ---------------------------------------------------------------------------
// run — config error paths
// ---------------------------------------------------------------------------

func TestRun_MissingBucket(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--format", "json"}, &out, &errBuf)
	if code != exitConfig {
		t.Errorf("missing bucket: exit=%d, want exitConfig(%d)", code, exitConfig)
	}
}

func TestRun_InvalidFormat(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--bucket", "b", "--format", "xml"}, &out, &errBuf)
	if code != exitConfig {
		t.Errorf("invalid format: exit=%d, want exitConfig(%d)", code, exitConfig)
	}
}

func TestRun_InvalidAfterDate(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--bucket", "b", "--after", "not-a-date"}, &out, &errBuf)
	if code != exitConfig {
		t.Errorf("invalid --after: exit=%d, want exitConfig(%d)", code, exitConfig)
	}
}

func TestRun_InvalidBeforeDate(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--bucket", "b", "--before", "26/04/2026"}, &out, &errBuf)
	if code != exitConfig {
		t.Errorf("invalid --before: exit=%d, want exitConfig(%d)", code, exitConfig)
	}
}

// ---------------------------------------------------------------------------
// printTable smoke test
// ---------------------------------------------------------------------------

func TestPrintTable_NoViolations(t *testing.T) {
	retain := time.Now().UTC().Add(100 * 24 * time.Hour)
	report := Report{
		GeneratedAt:    time.Now().UTC(),
		Bucket:         "test-bucket",
		Prefix:         "shadowai/evidence",
		RequireLock:    true,
		TotalBundles:   1,
		CompliantCount: 1,
		Bundles: []BundleRecord{{
			Key: "shadowai/evidence/2026/04/26/global-20260426-020001.zip",
			BundleType: "global", SizeBytes: 12345,
			LockMode: "COMPLIANCE", RetainUntil: &retain, Compliant: true,
		}},
	}
	var buf bytes.Buffer
	printTable(&buf, report)
	out := buf.String()
	if !strings.Contains(out, "COMPLIANCE") {
		t.Error("table should contain COMPLIANCE")
	}
	if !strings.Contains(out, "OK") {
		t.Error("table should contain OK status")
	}
}

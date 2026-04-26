package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── Manifest + hash helpers ────────────────────────────────────────────────

func TestComputeFileSHA256_SingleFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	hashes, err := computeFileSHA256(dir)
	if err != nil {
		t.Fatalf("computeFileSHA256: %v", err)
	}
	if _, ok := hashes["test.txt"]; !ok {
		t.Error("expected test.txt in hashes")
	}
	if hashes["test.txt"] == "" {
		t.Error("hash is empty")
	}
}

func TestComputeFileSHA256_SkipsManifest(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{}`), 0o644)
	os.WriteFile(filepath.Join(dir, "other.txt"), []byte("data"), 0o644)
	hashes, _ := computeFileSHA256(dir)
	if _, ok := hashes["manifest.json"]; ok {
		t.Error("manifest.json should be excluded from file hashes")
	}
	if _, ok := hashes["other.txt"]; !ok {
		t.Error("other.txt should be included")
	}
}

func TestWriteManifest_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	m := &PackageManifest{
		SchemaVersion: "1",
		Generator:     "test",
		Period:        Period{From: "2026-01-01", To: "2026-03-31"},
		Controls: []ControlEntry{
			{ID: "test_control", Status: ControlCollected, File: "test.json"},
		},
		FileSHA256: map[string]string{"test.json": "abc123"},
	}
	if err := writeManifest(dir, m); err != nil {
		t.Fatalf("writeManifest: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest.json: %v", err)
	}
	var got PackageManifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SchemaVersion != "1" {
		t.Errorf("schema_version = %q, want 1", got.SchemaVersion)
	}
	if len(got.Controls) != 1 || got.Controls[0].ID != "test_control" {
		t.Errorf("controls mismatch: %+v", got.Controls)
	}
}

// ── Templates ─────────────────────────────────────────────────────────────

func TestAccessReviewChecklist_ContainsPeriod(t *testing.T) {
	out := accessReviewChecklist("2026-01-01", "2026-03-31")
	if !strings.Contains(out, "2026-01-01") || !strings.Contains(out, "2026-03-31") {
		t.Error("checklist does not contain period dates")
	}
	if !strings.Contains(out, "Access Review") {
		t.Error("checklist missing title")
	}
}

func TestIncidentAlertReviewChecklist_ContainsPeriod(t *testing.T) {
	out := incidentAlertReviewChecklist("2026-01-01", "2026-03-31")
	if !strings.Contains(out, "2026-01-01") {
		t.Error("incident checklist missing from-date")
	}
	if !strings.Contains(out, "EvidenceExportJobFailed") {
		t.Error("incident checklist missing evidence export section")
	}
}

func TestCIReleaseChecklist_ContainsPeriod(t *testing.T) {
	out := ciReleaseChecklist("2026-01-01", "2026-03-31")
	if !strings.Contains(out, "2026-01-01") {
		t.Error("CI checklist missing period")
	}
	if !strings.Contains(out, "helm-validate") {
		t.Error("CI checklist missing helm-validate check")
	}
}

// ── run() integration ─────────────────────────────────────────────────────

func TestRun_MissingFrom(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--to", "2026-03-31", "--output", t.TempDir()}, &out, &errOut)
	if code != exitError {
		t.Errorf("missing --from: exit=%d, want exitError(%d)", code, exitError)
	}
}

func TestRun_MissingTo(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--from", "2026-01-01", "--output", t.TempDir()}, &out, &errOut)
	if code != exitError {
		t.Errorf("missing --to: exit=%d, want exitError(%d)", code, exitError)
	}
}

func TestRun_MissingOutput(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--from", "2026-01-01", "--to", "2026-03-31"}, &out, &errOut)
	if code != exitError {
		t.Errorf("missing --output: exit=%d, want exitError(%d)", code, exitError)
	}
}

func TestRun_InvalidFormat(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{
		"--from", "2026-01-01", "--to", "2026-03-31",
		"--output", t.TempDir(), "--format", "xml",
	}, &out, &errOut)
	if code != exitError {
		t.Errorf("invalid format: exit=%d, want exitError(%d)", code, exitError)
	}
}

func TestRun_InvalidDate(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{
		"--from", "not-a-date", "--to", "2026-03-31", "--output", t.TempDir(),
	}, &out, &errOut)
	if code != exitError {
		t.Errorf("invalid date: exit=%d, want exitError(%d)", code, exitError)
	}
}

func TestRun_DirFormat_GeneratesPackage(t *testing.T) {
	outDir := t.TempDir()
	var out, errOut bytes.Buffer

	// No DB or S3 credentials → all runtime controls not_collected.
	// --allow-incomplete to avoid exit 1.
	code := run([]string{
		"--from", "2026-01-01",
		"--to", "2026-03-31",
		"--output", outDir,
		"--format", "dir",
		"--allow-incomplete",
	}, &out, &errOut)

	if code != exitOK {
		t.Fatalf("exit=%d\nstdout: %s\nstderr: %s", code, out.String(), errOut.String())
	}

	// manifest.json must exist.
	manifestPath := filepath.Join(outDir, "manifest.json")
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("manifest.json missing: %v", err)
	}

	// Parse manifest.
	data, _ := os.ReadFile(manifestPath)
	var m PackageManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}

	if m.SchemaVersion != pkgSchemaVersion {
		t.Errorf("schema_version = %q, want %q", m.SchemaVersion, pkgSchemaVersion)
	}
	if m.Period.From != "2026-01-01" || m.Period.To != "2026-03-31" {
		t.Errorf("period = %+v", m.Period)
	}
	if len(m.Controls) == 0 {
		t.Error("controls list is empty")
	}
	if len(m.FileSHA256) == 0 {
		t.Error("file_sha256 map is empty")
	}

	// At least one checklist template must be collected.
	templateCount := 0
	for _, c := range m.Controls {
		if c.Status == ControlTemplate {
			templateCount++
		}
	}
	if templateCount == 0 {
		t.Error("no template controls in manifest")
	}

	// Checklist files must exist.
	if _, err := os.Stat(filepath.Join(outDir, "checklists", "access-review-checklist.md")); err != nil {
		t.Error("access-review-checklist.md missing")
	}
	if _, err := os.Stat(filepath.Join(outDir, "checklists", "incident-alert-review-checklist.md")); err != nil {
		t.Error("incident-alert-review-checklist.md missing")
	}
	if _, err := os.Stat(filepath.Join(outDir, "checklists", "ci-release-checklist.md")); err != nil {
		t.Error("ci-release-checklist.md missing")
	}

	// not_collected.json must exist (runtime controls not available without creds).
	if _, err := os.Stat(filepath.Join(outDir, "evidence", "not_collected.json")); err != nil {
		t.Error("evidence/not_collected.json missing")
	}

	t.Logf("manifest: %d controls (%d templates, %d not_collected, generator=%s)",
		len(m.Controls), templateCount,
		func() int {
			n := 0
			for _, c := range m.Controls {
				if c.Status == ControlNotCollected {
					n++
				}
			}
			return n
		}(),
		m.Generator)
}

func TestRun_ZipFormat_CreatesZip(t *testing.T) {
	outZip := filepath.Join(t.TempDir(), "evidence.zip")
	var out, errOut bytes.Buffer

	code := run([]string{
		"--from", "2026-01-01", "--to", "2026-03-31",
		"--output", outZip, "--format", "zip",
		"--allow-incomplete",
	}, &out, &errOut)

	if code != exitOK {
		t.Fatalf("exit=%d\nstderr: %s", code, errOut.String())
	}
	info, err := os.Stat(outZip)
	if err != nil {
		t.Fatalf("zip not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("zip file is empty")
	}
}

func TestRun_JSONFormat_CreatesJSON(t *testing.T) {
	outJSON := filepath.Join(t.TempDir(), "evidence.json")
	var out, errOut bytes.Buffer

	code := run([]string{
		"--from", "2026-01-01", "--to", "2026-03-31",
		"--output", outJSON, "--format", "json",
		"--allow-incomplete",
	}, &out, &errOut)

	if code != exitOK {
		t.Fatalf("exit=%d\nstderr: %s", code, errOut.String())
	}
	data, err := os.ReadFile(outJSON)
	if err != nil {
		t.Fatalf("json not created: %v", err)
	}
	var pkg jsonPackage
	if err := json.Unmarshal(data, &pkg); err != nil {
		t.Fatalf("unmarshal json package: %v", err)
	}
	if pkg.Manifest == nil {
		t.Error("manifest missing from json package")
	}
	if len(pkg.Files) == 0 {
		t.Error("files map empty in json package")
	}
}

func TestRun_NotCollected_ExitsIncomplete(t *testing.T) {
	var out, errOut bytes.Buffer
	// No --allow-incomplete → exit 1 because runtime controls can't be collected.
	code := run([]string{
		"--from", "2026-01-01", "--to", "2026-03-31",
		"--output", t.TempDir(), "--format", "dir",
	}, &out, &errOut)

	if code != exitIncomplete {
		t.Errorf("not_collected without --allow-incomplete: exit=%d, want exitIncomplete(%d)", code, exitIncomplete)
	}
}

func TestRun_AllowIncomplete_ExitsOK(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{
		"--from", "2026-01-01", "--to", "2026-03-31",
		"--output", t.TempDir(), "--format", "dir",
		"--allow-incomplete",
	}, &out, &errOut)

	if code != exitOK {
		t.Errorf("--allow-incomplete: exit=%d, want exitOK(%d)", code, exitOK)
	}
}

package evidencebundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWriteNDJSON_RoundTrip verifies that WriteNDJSON produces one JSON
// object per line, parseable back to the original struct.
func TestWriteNDJSON_RoundTrip(t *testing.T) {
	anchors := []AnchorLine{
		{ID: "a1", Table: "audit_logs", SeqLo: 1, SeqHi: 10, RowCount: 10, MerkleRootHex: "aabb", CreatedAt: time.Unix(0, 0).UTC()},
		{ID: "a2", Table: "audit_logs", SeqLo: 11, SeqHi: 20, RowCount: 10, MerkleRootHex: "ccdd", CreatedAt: time.Unix(0, 0).UTC()},
	}

	var sb strings.Builder
	if err := WriteNDJSON(&sb, anchors); err != nil {
		t.Fatalf("WriteNDJSON: %v", err)
	}

	lines := strings.Split(strings.TrimRight(sb.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), sb.String())
	}
	for i, line := range lines {
		var got AnchorLine
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Errorf("line %d: unmarshal failed: %v (content: %q)", i, err, line)
			continue
		}
		if got.ID != anchors[i].ID {
			t.Errorf("line %d: ID = %q, want %q", i, got.ID, anchors[i].ID)
		}
	}
}

// TestWriteNDJSON_Empty verifies that an empty slice produces no output.
func TestWriteNDJSON_Empty(t *testing.T) {
	var sb strings.Builder
	if err := WriteNDJSON(&sb, []AnchorLine{}); err != nil {
		t.Fatalf("WriteNDJSON empty: %v", err)
	}
	if sb.Len() != 0 {
		t.Errorf("expected empty output for empty slice, got %q", sb.String())
	}
}

// TestWriteNDJSON_ChainInventory verifies ChainInventoryLine serialization.
func TestWriteNDJSON_ChainInventory(t *testing.T) {
	entries := []ChainInventoryLine{
		{Table: "audit_logs", SeqNo: 1, RowIDHash: "aabbcc", RowHashHex: "ddeeff"},
		{Table: "admin_event_logs", SeqNo: 2, RowIDHash: "112233", RowHashHex: "445566"},
	}
	var sb strings.Builder
	if err := WriteNDJSON(&sb, entries); err != nil {
		t.Fatalf("WriteNDJSON: %v", err)
	}
	lines := strings.Split(strings.TrimRight(sb.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	var got ChainInventoryLine
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SeqNo != 1 || got.Table != "audit_logs" {
		t.Errorf("unexpected values: %+v", got)
	}
}

// TestFileSHA256 writes a known file and verifies the digest.
func TestFileSHA256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := FileSHA256(path)
	if err != nil {
		t.Fatalf("FileSHA256: %v", err)
	}
	// SHA256("hello\n") known value.
	const want = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
	if got != want {
		t.Errorf("digest = %q, want %q", got, want)
	}
}

// TestFileSHA256_NonExistent returns an error for missing file.
func TestFileSHA256_NonExistent(t *testing.T) {
	_, err := FileSHA256("/does/not/exist/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

// TestDBFingerprint_Deterministic verifies same input produces same output.
func TestDBFingerprint_Deterministic(t *testing.T) {
	a := DBFingerprint("db.internal:5432", "shadowai")
	b := DBFingerprint("db.internal:5432", "shadowai")
	if a != b {
		t.Errorf("non-deterministic: %q != %q", a, b)
	}
}

// TestDBFingerprint_DistinctInputs verifies different inputs produce different digests.
func TestDBFingerprint_DistinctInputs(t *testing.T) {
	a := DBFingerprint("db1.internal:5432", "shadowai")
	b := DBFingerprint("db2.internal:5432", "shadowai")
	if a == b {
		t.Error("different hosts must produce different fingerprints")
	}
}

// TestDBFingerprint_NoCredentials verifies the fingerprint does not contain host or dbname in plain text.
func TestDBFingerprint_NoCredentials(t *testing.T) {
	fp := DBFingerprint("db.internal:5432", "shadowai")
	if strings.Contains(fp, "shadowai") || strings.Contains(fp, "db.internal") {
		t.Errorf("fingerprint must not contain plain-text credentials: %q", fp)
	}
	// Must be a 64-char hex string (SHA256 = 32 bytes).
	if len(fp) != 64 {
		t.Errorf("fingerprint length = %d, want 64 (hex SHA256)", len(fp))
	}
}

// TestWriteManifest writes a manifest and reads it back.
func TestWriteManifest(t *testing.T) {
	dir := t.TempDir()
	m := &BundleManifest{
		Version:    BundleVersion,
		ExportTime: time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC),
		Tables:     []string{"audit_logs", "admin_event_logs"},
		FileSHA256: map[string]string{"anchors.jsonl": "aabbcc"},
	}
	if err := WriteManifest(dir, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "bundle_manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var got BundleManifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if got.Version != BundleVersion {
		t.Errorf("version = %q, want %q", got.Version, BundleVersion)
	}
	if len(got.Tables) != 2 {
		t.Errorf("tables = %v, want 2 entries", got.Tables)
	}
	if got.FileSHA256["anchors.jsonl"] != "aabbcc" {
		t.Errorf("file hash = %q, want aabbcc", got.FileSHA256["anchors.jsonl"])
	}
}

// TestComputeBundleHashes computes hashes and verifies manifest is excluded.
func TestComputeBundleHashes(t *testing.T) {
	dir := t.TempDir()
	// Write some files.
	if err := os.WriteFile(filepath.Join(dir, "anchors.jsonl"), []byte(`{"id":"a1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle_manifest.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "reports"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "reports", "anchor_verify_audit_logs.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	hashes, err := ComputeBundleHashes(dir)
	if err != nil {
		t.Fatalf("ComputeBundleHashes: %v", err)
	}
	// bundle_manifest.json must be excluded.
	if _, ok := hashes["bundle_manifest.json"]; ok {
		t.Error("bundle_manifest.json must not appear in file_sha256")
	}
	// anchors.jsonl and reports file must be present.
	if _, ok := hashes["anchors.jsonl"]; !ok {
		t.Error("anchors.jsonl must appear in file_sha256")
	}
	if _, ok := hashes[filepath.Join("reports", "anchor_verify_audit_logs.json")]; !ok {
		t.Error("reports/anchor_verify_audit_logs.json must appear in file_sha256")
	}
	// Each value must be a 64-char hex string.
	for k, v := range hashes {
		if len(v) != 64 {
			t.Errorf("hash for %q has length %d, want 64", k, len(v))
		}
	}
}

// TestWriteReadme writes README.txt and checks basic content.
func TestWriteReadme(t *testing.T) {
	t.Run("without_pubkey", func(t *testing.T) {
		dir := t.TempDir()
		if err := WriteReadme(dir, []string{"audit_logs"}, false); err != nil {
			t.Fatalf("WriteReadme: %v", err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "README.txt"))
		if err != nil {
			t.Fatalf("read README: %v", err)
		}
		content := string(data)
		if !strings.Contains(content, "chain_inventory") {
			t.Error("README should mention chain_inventory")
		}
		if !strings.Contains(content, "AUDIT_CHAIN_SECRET") {
			t.Error("README should mention AUDIT_CHAIN_SECRET limitation")
		}
		if !strings.Contains(content, "none") {
			t.Error("README should say no offline verify without pubkey")
		}
	})

	t.Run("with_pubkey", func(t *testing.T) {
		dir := t.TempDir()
		if err := WriteReadme(dir, []string{"audit_logs", "admin_event_logs"}, true); err != nil {
			t.Fatalf("WriteReadme: %v", err)
		}
		data, _ := os.ReadFile(filepath.Join(dir, "README.txt"))
		content := string(data)
		if !strings.Contains(content, "Ed25519") {
			t.Error("README should mention Ed25519 offline verification")
		}
		if !strings.Contains(content, "public_key.b64") {
			t.Error("README should mention public_key.b64")
		}
	})
}

// TestAnchorLine_SignatureHex_OmitEmpty verifies SignatureHex is omitted
// when empty (unsigned anchors do not pollute output).
func TestAnchorLine_SignatureHex_OmitEmpty(t *testing.T) {
	a := AnchorLine{ID: "x", Table: "audit_logs", SeqLo: 1, SeqHi: 10}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "signature_hex") {
		t.Errorf("unsigned anchor must not include signature_hex field: %s", data)
	}
}

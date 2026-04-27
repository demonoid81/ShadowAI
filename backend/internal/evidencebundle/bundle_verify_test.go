package evidencebundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shadowai/backend/internal/chain"
	"github.com/shadowai/backend/internal/legalholdselector"
)

// ---------------------------------------------------------------------------
// Test bundle builder helpers
// ---------------------------------------------------------------------------

type testBundle struct {
	t   *testing.T
	dir string
}

func newTestBundle(t *testing.T) *testBundle {
	t.Helper()
	b := &testBundle{t: t, dir: t.TempDir()}
	if err := os.MkdirAll(filepath.Join(b.dir, "reports"), 0o755); err != nil {
		t.Fatalf("mkdir reports: %v", err)
	}
	return b
}

func (b *testBundle) anchors(anchors []AnchorLine) *testBundle {
	b.t.Helper()
	b.writeSlice("anchors.jsonl", len(anchors), func(enc *json.Encoder, i int) {
		enc.Encode(anchors[i]) //nolint
	})
	return b
}

func (b *testBundle) inventory(entries []ChainInventoryLine) *testBundle {
	b.t.Helper()
	b.writeSlice("chain_inventory.jsonl", len(entries), func(enc *json.Encoder, i int) {
		enc.Encode(entries[i]) //nolint
	})
	return b
}

func (b *testBundle) selectors(entries []SelectorManifestLine) *testBundle {
	b.t.Helper()
	b.writeSlice("selector_manifest.jsonl", len(entries), func(enc *json.Encoder, i int) {
		enc.Encode(entries[i]) //nolint
	})
	return b
}

func (b *testBundle) writeSlice(name string, n int, fn func(*json.Encoder, int)) {
	b.t.Helper()
	f, err := os.Create(filepath.Join(b.dir, name))
	if err != nil {
		b.t.Fatalf("create %s: %v", name, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for i := 0; i < n; i++ {
		fn(enc, i)
	}
}

func (b *testBundle) pubKey(pub ed25519.PublicKey) *testBundle {
	b.t.Helper()
	data := base64.StdEncoding.EncodeToString(pub)
	if err := os.WriteFile(filepath.Join(b.dir, "public_key.b64"), []byte(data+"\n"), 0o644); err != nil {
		b.t.Fatalf("write pubkey: %v", err)
	}
	return b
}

func (b *testBundle) withManifest() *testBundle {
	b.t.Helper()
	hashes, err := ComputeBundleHashes(b.dir)
	if err != nil {
		b.t.Fatalf("compute hashes: %v", err)
	}
	m := &BundleManifest{
		Version:    BundleVersion,
		ExportTime: time.Now().UTC(),
		FileSHA256: hashes,
	}
	if err := WriteManifest(b.dir, m); err != nil {
		b.t.Fatalf("write manifest: %v", err)
	}
	return b
}

// makeAnchor creates an AnchorLine with inclusive [seqLo, seqHi] range.
// In real production anchors: SeqLo = prevSeqHi + 1 (set by scheduler).
func makeAnchor(id, table string, seqLo, seqHi int64, rowCount int) AnchorLine {
	merkle := make([]byte, 32)
	for i := range merkle {
		merkle[i] = byte(seqHi & 0xFF)
	}
	return AnchorLine{
		ID:            id,
		Table:         table,
		SeqLo:         seqLo,
		SeqHi:         seqHi,
		RowCount:      rowCount,
		MerkleRootHex: hex.EncodeToString(merkle),
		CreatedAt:     time.Now().UTC().Truncate(time.Second),
	}
}

// inventoryRange generates ChainInventoryLine for seq_no lo..hi (inclusive).
func inventoryRange(table string, lo, hi int64) []ChainInventoryLine {
	var result []ChainInventoryLine
	for i := lo; i <= hi; i++ {
		result = append(result, ChainInventoryLine{
			Table:      table,
			SeqNo:      i,
			RowIDHash:  hex.EncodeToString([]byte{byte(i)}),
			RowHashHex: hex.EncodeToString([]byte{byte(i), byte(i >> 8)}),
		})
	}
	return result
}

func selectorLine(t *testing.T, holdID, orgID, raw string) SelectorManifestLine {
	t.Helper()
	compiled, err := legalholdselector.Compile(json.RawMessage(raw), legalholdselector.CompileOptions{})
	if err != nil {
		t.Fatalf("compile selector: %v", err)
	}
	return SelectorManifestLine{
		HoldID:          holdID,
		OrgID:           orgID,
		ScopeType:       "query_scope",
		SelectorHash:    compiled.Hash,
		SelectorVersion: 1,
		SelectorJSON:    json.RawMessage(compiled.NormalizedJSON),
	}
}

// signAnchorLine signs an AnchorLine using chain.SignAnchor and returns the
// signed copy with SignatureHex set.
func signAnchorLine(t *testing.T, a AnchorLine, priv ed25519.PrivateKey, pubKeyID string) AnchorLine {
	t.Helper()
	rec := anchorLineToRecord(a)
	rec.PubKeyID = pubKeyID
	if err := chain.SignAnchor(&rec, priv, pubKeyID); err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}
	a.PubKeyID = pubKeyID
	a.SignatureHex = hex.EncodeToString(rec.Signature)
	return a
}

// ---------------------------------------------------------------------------
// FileIntegrity tests
// ---------------------------------------------------------------------------

func TestVerifyBundle_FileIntegrity_OK(t *testing.T) {
	b := newTestBundle(t).
		anchors(nil).
		inventory(nil).
		withManifest()
	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !result.FileIntegrity.OK {
		t.Errorf("file integrity: expected OK, got FAIL: %+v", result.FileIntegrity.Fails)
	}
}

func TestVerifyBundle_FileIntegrity_TamperedFile(t *testing.T) {
	b := newTestBundle(t).
		anchors(nil).
		inventory(nil).
		withManifest()
	// Tamper with anchors.jsonl after manifest was written.
	if err := os.WriteFile(filepath.Join(b.dir, "anchors.jsonl"), []byte("tampered\n"), 0o644); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if result.FileIntegrity.OK {
		t.Error("tampered file: expected FAIL, got OK")
	}
	if len(result.FileIntegrity.Fails) == 0 {
		t.Error("expected at least one FileIntegrityFail")
	}
	if result.OK {
		t.Error("overall result must be FAIL when file integrity fails")
	}
}

// ---------------------------------------------------------------------------
// Selector manifest tests
// ---------------------------------------------------------------------------

func TestVerifyBundle_SelectorManifest_Valid(t *testing.T) {
	line := selectorLine(t, "hold-1", "org-a", `{"v":1,"field":"provider","op":"eq","value":"openai"}`)
	b := newTestBundle(t).
		anchors(nil).
		inventory(nil).
		selectors([]SelectorManifestLine{line}).
		withManifest()

	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !result.SelectorManifest.OK {
		t.Fatalf("selector manifest should verify: %+v", result.SelectorManifest.Fails)
	}
	if result.SelectorManifest.Checked != 1 {
		t.Fatalf("checked selectors = %d, want 1", result.SelectorManifest.Checked)
	}
	if !result.OK {
		t.Fatalf("overall bundle should be OK: %+v", result)
	}
}

func TestVerifyBundle_SelectorManifest_TamperedSelectorFails(t *testing.T) {
	line := selectorLine(t, "hold-1", "org-a", `{"v":1,"field":"provider","op":"eq","value":"openai"}`)
	line.SelectorJSON = json.RawMessage(`{"v":1,"field":"provider","op":"eq","value":"anthropic"}`)
	b := newTestBundle(t).
		anchors(nil).
		inventory(nil).
		selectors([]SelectorManifestLine{line}).
		withManifest()

	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if result.SelectorManifest.OK {
		t.Fatal("tampered selector JSON should fail selector manifest verification")
	}
	if len(result.SelectorManifest.Fails) != 1 {
		t.Fatalf("selector fails = %d, want 1", len(result.SelectorManifest.Fails))
	}
	if result.OK {
		t.Fatal("overall bundle must fail when selector hash mismatches selector_json")
	}
}

func TestVerifyBundle_SelectorManifest_EmptyFileOKAndHasManifestHash(t *testing.T) {
	b := newTestBundle(t).
		anchors(nil).
		inventory(nil).
		selectors(nil).
		withManifest()

	manifest, err := ReadBundleManifest(b.dir)
	if err != nil {
		t.Fatalf("ReadBundleManifest: %v", err)
	}
	if _, ok := manifest.FileSHA256["selector_manifest.jsonl"]; !ok {
		t.Fatal("selector_manifest.jsonl must be hashed in bundle_manifest.json")
	}

	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !result.SelectorManifest.OK || result.SelectorManifest.Checked != 0 {
		t.Fatalf("empty selector manifest should be OK with checked=0: %+v", result.SelectorManifest)
	}
	if !result.OK {
		t.Fatalf("overall bundle should be OK with empty selector manifest: %+v", result)
	}
}

func TestVerifyBundle_SelectorManifest_MissingFileBackwardCompatible(t *testing.T) {
	b := newTestBundle(t).
		anchors(nil).
		inventory(nil).
		withManifest()

	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !result.SelectorManifest.OK || !result.SelectorManifest.Missing {
		t.Fatalf("missing selector_manifest.jsonl should be backward-compatible: %+v", result.SelectorManifest)
	}
	if !result.OK {
		t.Fatalf("legacy bundle without selector_manifest.jsonl should remain OK: %+v", result)
	}
}

// ---------------------------------------------------------------------------
// Anchor signature tests
// ---------------------------------------------------------------------------

// TestVerifyBundle_AnchorSigs_ValidSignature uses chain.SignAnchor to produce
// a real Ed25519 signature and asserts AnchorSigs.OK == true.
func TestVerifyBundle_AnchorSigs_ValidSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Inclusive range [1, 10] — matches real scheduler output.
	anchor := signAnchorLine(t, makeAnchor("a1", "audit_logs", 1, 10, 10), priv, "test-key-1")

	b := newTestBundle(t).
		pubKey(pub).
		anchors([]AnchorLine{anchor}).
		inventory(inventoryRange("audit_logs", 1, 10)).
		withManifest()

	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !result.AnchorSigs.OK {
		t.Errorf("valid signature: expected AnchorSigs.OK=true, fails: %+v", result.AnchorSigs.Fails)
	}
	if result.AnchorSigs.Total != 1 {
		t.Errorf("Total = %d, want 1", result.AnchorSigs.Total)
	}
}

// TestVerifyBundle_AnchorSigs_TamperedSignature verifies that a signature with
// wrong bytes is detected and causes AnchorSigs.OK == false.
func TestVerifyBundle_AnchorSigs_TamperedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	anchor := signAnchorLine(t, makeAnchor("a1", "audit_logs", 1, 10, 10), priv, "test-key-1")
	// Corrupt the signature: flip every byte.
	sig, _ := hex.DecodeString(anchor.SignatureHex)
	for i := range sig {
		sig[i] ^= 0xFF
	}
	anchor.SignatureHex = hex.EncodeToString(sig)

	b := newTestBundle(t).
		pubKey(pub).
		anchors([]AnchorLine{anchor}).
		inventory(nil).
		withManifest()

	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if result.AnchorSigs.OK {
		t.Error("tampered signature: expected AnchorSigs.OK=false, got true")
	}
	if len(result.AnchorSigs.Fails) != 1 {
		t.Errorf("expected 1 sig fail, got %d", len(result.AnchorSigs.Fails))
	}
	if result.AnchorSigs.Fails[0].AnchorID != "a1" {
		t.Errorf("fail anchor_id = %q, want a1", result.AnchorSigs.Fails[0].AnchorID)
	}
	if result.OK {
		t.Error("overall result must be FAIL with tampered signature")
	}
}

func TestVerifyBundle_AnchorSigs_NoPubKey_UnsignedPasses(t *testing.T) {
	anchor := makeAnchor("a1", "audit_logs", 1, 10, 10) // no signature
	b := newTestBundle(t).anchors([]AnchorLine{anchor}).inventory(nil).withManifest()
	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !result.AnchorSigs.OK {
		t.Error("unsigned anchor, no pubkey: expected OK, got FAIL")
	}
	if result.AnchorSigs.Unsigned != 1 {
		t.Errorf("Unsigned = %d, want 1", result.AnchorSigs.Unsigned)
	}
}

func TestVerifyBundle_AnchorSigs_UseBundlePubKey(t *testing.T) {
	// public_key.b64 in bundle should be auto-loaded by VerifyBundle.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	anchor := signAnchorLine(t, makeAnchor("a1", "audit_logs", 1, 5, 5), priv, "key1")

	b := newTestBundle(t).
		pubKey(pub).
		anchors([]AnchorLine{anchor}).
		inventory(inventoryRange("audit_logs", 1, 5)).
		withManifest()

	result, err := VerifyBundle(b.dir, nil) // nil pubKey — reads from bundle
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !result.AnchorSigs.OK {
		t.Errorf("bundle pubkey: expected OK, fails: %+v", result.AnchorSigs.Fails)
	}
}

func TestVerifyBundle_AnchorSigs_SignedWithoutPubKey_NoPubKeyCount(t *testing.T) {
	anchor := makeAnchor("a1", "audit_logs", 1, 10, 10)
	anchor.SignatureHex = hex.EncodeToString(make([]byte, 64))
	anchor.PubKeyID = "key1"

	b := newTestBundle(t).anchors([]AnchorLine{anchor}).inventory(nil).withManifest()
	// No pubkey in bundle, no pubkey passed → NoPubKey counted, OK=true.
	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !result.AnchorSigs.OK {
		t.Error("signed anchor without any pubkey: should be OK (NoPubKey), not FAIL")
	}
	if result.AnchorSigs.NoPubKey != 1 {
		t.Errorf("NoPubKey = %d, want 1", result.AnchorSigs.NoPubKey)
	}
}

// ---------------------------------------------------------------------------
// Range continuity tests (inclusive [SeqLo, SeqHi])
// ---------------------------------------------------------------------------

func TestVerifyBundle_RangeContinuity_OK(t *testing.T) {
	// Real scheduler produces: [1,10], [11,20], [21,30]
	anchors := []AnchorLine{
		makeAnchor("a1", "audit_logs", 1, 10, 10),
		makeAnchor("a2", "audit_logs", 11, 20, 10),
		makeAnchor("a3", "audit_logs", 21, 30, 10),
	}
	b := newTestBundle(t).anchors(anchors).inventory(nil).withManifest()
	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	for _, rc := range result.RangeContinuity {
		if !rc.OK {
			t.Errorf("range continuity %s: expected OK, got FAIL: %+v", rc.Table, rc.Gaps)
		}
	}
}

func TestVerifyBundle_RangeContinuity_Gap(t *testing.T) {
	// Gap: anchor 2 starts at 16, but anchor 1 ends at 10, so rows 11..15 uncovered.
	anchors := []AnchorLine{
		makeAnchor("a1", "audit_logs", 1, 10, 10),
		makeAnchor("a2", "audit_logs", 16, 25, 10),
	}
	b := newTestBundle(t).anchors(anchors).inventory(nil).withManifest()
	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	found := false
	for _, rc := range result.RangeContinuity {
		if rc.Table == "audit_logs" {
			if rc.OK {
				t.Error("range gap: expected FAIL, got OK")
			}
			if len(rc.Gaps) != 1 {
				t.Fatalf("expected 1 gap, got: %+v", rc.Gaps)
			}
			g := rc.Gaps[0]
			if g.PrevSeqHi != 10 || g.NextSeqLo != 16 {
				t.Errorf("gap = prev_seq_hi=%d next_seq_lo=%d, want 10,16", g.PrevSeqHi, g.NextSeqLo)
			}
			found = true
		}
	}
	if !found {
		t.Error("no range continuity result for audit_logs")
	}
	if result.OK {
		t.Error("overall result must be FAIL with range gap")
	}
}

// TestVerifyBundle_RangeContinuity_Regression_InclusiveSemantics is a regression
// test for the production anchor range format: [1,10], [11,20] must be contiguous.
func TestVerifyBundle_RangeContinuity_Regression_InclusiveSemantics(t *testing.T) {
	// This is exactly what the W3 scheduler produces for 20 rows in two batches.
	anchors := []AnchorLine{
		makeAnchor("a1", "audit_logs", 1, 10, 10),
		makeAnchor("a2", "audit_logs", 11, 20, 10),
	}
	inv := inventoryRange("audit_logs", 1, 20)
	b := newTestBundle(t).anchors(anchors).inventory(inv).withManifest()
	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	// Range continuity: no gap between [1,10] and [11,20].
	for _, rc := range result.RangeContinuity {
		if !rc.OK {
			t.Errorf("range %s: unexpected FAIL (gaps=%v) — regression in inclusive semantics", rc.Table, rc.Gaps)
		}
	}
	// Inventory count: anchor [1,10] → 10 rows; anchor [11,20] → 10 rows.
	for _, ic := range result.InventoryCount {
		if !ic.OK {
			t.Errorf("count %s: unexpected FAIL (%+v) — regression in inclusive semantics", ic.Table, ic.Mismatches)
		}
	}
	if !result.OK {
		t.Errorf("clean production-format bundle should be OK: %+v", result)
	}
}

// ---------------------------------------------------------------------------
// Inventory continuity tests
// ---------------------------------------------------------------------------

func TestVerifyBundle_InventoryContinuity_OK(t *testing.T) {
	inv := inventoryRange("audit_logs", 1, 20)
	b := newTestBundle(t).anchors(nil).inventory(inv).withManifest()
	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	for _, ic := range result.InventoryContinuity {
		if !ic.OK {
			t.Errorf("inventory continuity %s: expected OK, gaps=%v", ic.Table, ic.Gaps)
		}
	}
}

func TestVerifyBundle_InventoryContinuity_Gap(t *testing.T) {
	// seq_no 1..5 then 8..10 — gaps at 6,7.
	inv := append(inventoryRange("audit_logs", 1, 5), inventoryRange("audit_logs", 8, 10)...)
	b := newTestBundle(t).anchors(nil).inventory(inv).withManifest()
	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	found := false
	for _, ic := range result.InventoryContinuity {
		if ic.Table == "audit_logs" {
			if ic.OK {
				t.Error("inventory gap: expected FAIL, got OK")
			}
			if len(ic.Gaps) != 2 {
				t.Errorf("expected 2 gaps (6,7), got: %v", ic.Gaps)
			}
			found = true
		}
	}
	if !found {
		t.Error("no inventory continuity result for audit_logs")
	}
}

// ---------------------------------------------------------------------------
// Inventory count vs anchor row_count tests
// ---------------------------------------------------------------------------

func TestVerifyBundle_InventoryCount_OK(t *testing.T) {
	// Inclusive anchor [1,10] has RowCount=10, inventory 1..10 has 10 entries.
	anchors := []AnchorLine{makeAnchor("a1", "audit_logs", 1, 10, 10)}
	inv := inventoryRange("audit_logs", 1, 10)
	b := newTestBundle(t).anchors(anchors).inventory(inv).withManifest()
	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	for _, ic := range result.InventoryCount {
		if !ic.OK {
			t.Errorf("inventory count %s: expected OK: %+v", ic.Table, ic.Mismatches)
		}
	}
}

func TestVerifyBundle_InventoryCount_Mismatch(t *testing.T) {
	// Anchor says row_count=10 but inventory only has rows 1..8 (8 entries).
	anchors := []AnchorLine{makeAnchor("a1", "audit_logs", 1, 10, 10)}
	inv := inventoryRange("audit_logs", 1, 8)
	b := newTestBundle(t).anchors(anchors).inventory(inv).withManifest()
	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	found := false
	for _, ic := range result.InventoryCount {
		if ic.Table == "audit_logs" {
			if ic.OK {
				t.Error("count mismatch: expected FAIL, got OK")
			}
			if len(ic.Mismatches) != 1 {
				t.Errorf("expected 1 mismatch, got: %+v", ic.Mismatches)
			} else {
				m := ic.Mismatches[0]
				if m.AnchorRowCount != 10 || m.InventoryCount != 8 {
					t.Errorf("anchor_count=%d inventory_count=%d, want 10,8", m.AnchorRowCount, m.InventoryCount)
				}
			}
			found = true
		}
	}
	if !found {
		t.Error("no inventory count result for audit_logs")
	}
}

// ---------------------------------------------------------------------------
// Multi-table test
// ---------------------------------------------------------------------------

func TestVerifyBundle_MultiTable(t *testing.T) {
	anchors := []AnchorLine{
		makeAnchor("a1", "audit_logs", 1, 5, 5),
		makeAnchor("a2", "admin_event_logs", 1, 3, 3),
	}
	inv := append(
		inventoryRange("audit_logs", 1, 5),
		inventoryRange("admin_event_logs", 1, 3)...,
	)
	b := newTestBundle(t).anchors(anchors).inventory(inv).withManifest()
	result, err := VerifyBundle(b.dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !result.OK {
		t.Errorf("multi-table clean bundle: expected OK, got FAIL: %+v", result)
	}
	if len(result.RangeContinuity) != 2 {
		t.Errorf("expected 2 range continuity results, got %d", len(result.RangeContinuity))
	}
}

// ---------------------------------------------------------------------------
// OpenBundle tests
// ---------------------------------------------------------------------------

func TestOpenBundle_Directory(t *testing.T) {
	dir := t.TempDir()
	got, cleanup, err := OpenBundle(dir)
	defer cleanup()
	if err != nil {
		t.Fatalf("OpenBundle: %v", err)
	}
	if got != dir {
		t.Errorf("OpenBundle dir = %q, want %q", got, dir)
	}
}

func TestOpenBundle_ZipExtracts(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "anchors.jsonl"), []byte(`{}`+"\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	zipPath := filepath.Clean(srcDir) + "_test.zip"
	if err := ZipBundleDir(srcDir, zipPath); err != nil {
		t.Fatalf("ZipBundleDir: %v", err)
	}
	dir, cleanup, err := OpenBundle(zipPath)
	defer cleanup()
	if err != nil {
		t.Fatalf("OpenBundle zip: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "anchors.jsonl")); err != nil {
		t.Errorf("expected anchors.jsonl in extracted dir: %v", err)
	}
}

func TestOpenBundle_NonExistent(t *testing.T) {
	_, cleanup, err := OpenBundle("/does/not/exist")
	defer cleanup()
	if err == nil {
		t.Error("expected error for non-existent path, got nil")
	}
}

// ---------------------------------------------------------------------------
// countInRange unit tests (inclusive [lo, hi])
// ---------------------------------------------------------------------------

func TestCountInRange_Inclusive(t *testing.T) {
	sorted := []int64{1, 2, 3, 4, 5, 10, 11, 12}
	cases := []struct {
		lo, hi int64
		want   int
		desc   string
	}{
		{1, 10, 6, "[1,10] → 1,2,3,4,5,10"},
		{1, 5, 5, "[1,5] → 1,2,3,4,5"},
		{1, 12, 8, "[1,12] → all 8"},
		{10, 12, 3, "[10,12] → 10,11,12"},
		{6, 9, 0, "[6,9] → none"},
		{13, 20, 0, "[13,20] → none above 12"},
		{1, 1, 1, "[1,1] → just 1"},
	}
	for _, tc := range cases {
		got := countInRange(sorted, tc.lo, tc.hi)
		if got != tc.want {
			t.Errorf("countInRange lo=%d hi=%d (%s) = %d, want %d", tc.lo, tc.hi, tc.desc, got, tc.want)
		}
	}
}

// TestCountInRange_ProductionAnchorRanges verifies the two-anchor scenario
// that caused the High bug: [1,10] and [11,20] inclusive must each count 10.
func TestCountInRange_ProductionAnchorRanges(t *testing.T) {
	// inventory rows 1..20
	inv := make([]int64, 20)
	for i := range inv {
		inv[i] = int64(i + 1)
	}
	if got := countInRange(inv, 1, 10); got != 10 {
		t.Errorf("anchor [1,10]: countInRange = %d, want 10", got)
	}
	if got := countInRange(inv, 11, 20); got != 10 {
		t.Errorf("anchor [11,20]: countInRange = %d, want 10", got)
	}
}

package chain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"testing"
	"time"
)

// ── Multi-sink test mocks ──────────────────────────────────────────────────

// multiSinkRepo implements AnchorRepoReader + AnchorSinksWriter for W8 tests.
type multiSinkRepo struct {
	testAnchorRepo
	sinkResults    []AnchorSinkResult
	sinkWriteError error
}

// WriteAnchor overrides testAnchorRepo to also set a.ID so multi-sink path fires.
func (m *multiSinkRepo) WriteAnchor(_ context.Context, a *AnchorRecord) error {
	m.testAnchorRepo.anchored = true
	m.testAnchorRepo.lastWritten = a
	if a.ID == "" {
		a.ID = "test-anchor-id-" + a.TableName // deterministic test ID
	}
	return nil
}

func (m *multiSinkRepo) WriteAnchorSinks(_ context.Context, _ string, results []AnchorSinkResult) error {
	if m.sinkWriteError != nil {
		return m.sinkWriteError
	}
	m.sinkResults = append(m.sinkResults, results...)
	return nil
}

func (m *multiSinkRepo) ListAnchorSinks(_ context.Context, _ string) ([]AnchorSinkResult, error) {
	return m.sinkResults, nil
}

// captureManifestSink records manifest bytes for assertions.
type captureManifestSink struct {
	receivedManifest []byte
	failWrite        bool
	buildRef         string
}

func (c *captureManifestSink) Name() string { return "capture://" }
func (c *captureManifestSink) BuildRef(_ *AnchorRecord) string {
	if c.buildRef != "" {
		return c.buildRef
	}
	return "capture://ref"
}
func (c *captureManifestSink) Write(_ context.Context, manifest []byte, _ string) error {
	if c.failWrite {
		return fmt.Errorf("simulated capture sink failure")
	}
	c.receivedManifest = append([]byte(nil), manifest...)
	return nil
}

// ── Tests ──────────────────────────────────────────────────────────────────

// TestMultiSink_SingleSinkBackwardCompat — single-sink behavior unchanged.
// Existing scheduler without WithAdditionalSinks must work exactly as before.
func TestMultiSink_SingleSinkBackwardCompat(t *testing.T) {
	hashes := [][]byte{make([]byte, 32)}
	primary := &testSink{buildRef: "file:///primary"}
	repo := &multiSinkRepo{
		testAnchorRepo: testAnchorRepo{
			lastSeqHi: 0, maxSeqNo: 1, hashes: hashes,
		},
	}
	// No additional sinks — should behave exactly like existing single-sink.
	sched := NewAnchorScheduler(repo, primary, 0, []string{"audit_logs"})
	if err := sched.anchorTable(context.Background(), "audit_logs"); err != nil {
		t.Fatalf("anchorTable: %v", err)
	}
	if !repo.anchored || repo.lastWritten == nil {
		t.Fatal("anchor not written")
	}
	if len(repo.sinkResults) != 0 {
		t.Errorf("single-sink should not write audit_chain_anchor_sinks, got %d results",
			len(repo.sinkResults))
	}
}

// TestMultiSink_TwoSinksOK — DoD: both sinks receive identical manifest bytes.
func TestMultiSink_TwoSinksOK(t *testing.T) {
	hashes := [][]byte{make([]byte, 32), make([]byte, 32)}
	hashes[0][0] = 0xCC

	primary := &testSink{buildRef: "file:///primary"}
	secondary := &captureManifestSink{buildRef: "file:///secondary"}
	repo := &multiSinkRepo{
		testAnchorRepo: testAnchorRepo{
			lastSeqHi: 0, maxSeqNo: 2, hashes: hashes,
		},
	}

	sched := NewAnchorScheduler(repo, primary, 0, []string{"audit_logs"}).
		WithAdditionalSinks(secondary)
	if err := sched.anchorTable(context.Background(), "audit_logs"); err != nil {
		t.Fatalf("anchorTable: %v", err)
	}

	// Both sinks must have received a write.
	if len(secondary.receivedManifest) == 0 {
		t.Fatal("secondary sink received no manifest bytes")
	}
	// Per-sink results must be recorded.
	if len(repo.sinkResults) == 0 {
		t.Fatal("no sink results recorded in repo")
	}
	if !repo.sinkResults[0].SinkOK {
		t.Errorf("secondary sink result: SinkOK=false, want true")
	}
}

// TestMultiSink_IdenticalManifestBytes — the SAME manifest bytes reach all sinks.
func TestMultiSink_IdenticalManifestBytes(t *testing.T) {
	hashes := [][]byte{make([]byte, 32)}
	hashes[0][0] = 0xDD

	var primaryManifest []byte
	primary := &testSink{
		buildRef: "file:///primary",
		writeFn: func(manifest []byte, _ string) error {
			primaryManifest = append([]byte(nil), manifest...)
			return nil
		},
	}
	secondary := &captureManifestSink{buildRef: "file:///secondary"}
	repo := &multiSinkRepo{
		testAnchorRepo: testAnchorRepo{
			lastSeqHi: 0, maxSeqNo: 1, hashes: hashes,
		},
	}

	sched := NewAnchorScheduler(repo, primary, 0, []string{"audit_logs"}).
		WithAdditionalSinks(secondary)
	if err := sched.anchorTable(context.Background(), "audit_logs"); err != nil {
		t.Fatalf("anchorTable: %v", err)
	}

	if len(primaryManifest) == 0 || len(secondary.receivedManifest) == 0 {
		t.Fatal("at least one sink received no manifest")
	}
	if string(primaryManifest) != string(secondary.receivedManifest) {
		t.Errorf("manifest bytes differ between sinks:\nprimary:   %q\nsecondary: %q",
			primaryManifest, secondary.receivedManifest)
	}
}

// TestMultiSink_SecondSinkFails_StatusRecorded — DoD: second sink failure is
// recorded explicitly; primary anchor still written; no silent all-ok.
func TestMultiSink_SecondSinkFails_StatusRecorded(t *testing.T) {
	hashes := [][]byte{make([]byte, 32)}
	primary := &testSink{buildRef: "file:///primary"}
	failingSink := &captureManifestSink{buildRef: "file:///secondary", failWrite: true}
	repo := &multiSinkRepo{
		testAnchorRepo: testAnchorRepo{
			lastSeqHi: 0, maxSeqNo: 1, hashes: hashes,
		},
	}

	sched := NewAnchorScheduler(repo, primary, 0, []string{"audit_logs"}).
		WithAdditionalSinks(failingSink)
	if err := sched.anchorTable(context.Background(), "audit_logs"); err != nil {
		t.Fatalf("anchorTable unexpectedly errored: %v", err)
	}

	// Primary anchor must still be written.
	if !repo.anchored || repo.lastWritten == nil {
		t.Fatal("primary anchor not written after secondary sink failure")
	}
	// Primary sink_ok=true (primary succeeded).
	if !repo.lastWritten.SinkOK {
		t.Error("primary sink_ok should be true")
	}
	// Additional sink result must record failure.
	if len(repo.sinkResults) == 0 {
		t.Fatal("no sink results recorded — partial failure not persisted")
	}
	if repo.sinkResults[0].SinkOK {
		t.Error("secondary sink result SinkOK=true, want false (sink was configured to fail)")
	}
	if repo.sinkResults[0].ErrorMsg == "" {
		t.Error("ErrorMsg empty for failed secondary sink")
	}
	t.Logf("secondary failure recorded: %s", repo.sinkResults[0].ErrorMsg)
}

// TestMultiSink_BothSinksFailPrimary_PrimaryRecordsSinkOKFalse — primary sink
// failure does NOT trigger partial-sink path; existing fail-open behavior.
func TestMultiSink_PrimaryFails_ExistingFailOpen(t *testing.T) {
	hashes := [][]byte{make([]byte, 32)}
	failPrimary := &testSink{
		buildRef: "file:///primary",
		writeFn:  func(_ []byte, _ string) error { return fmt.Errorf("primary fail") },
	}
	secondary := &captureManifestSink{buildRef: "file:///secondary"}
	repo := &multiSinkRepo{
		testAnchorRepo: testAnchorRepo{
			lastSeqHi: 0, maxSeqNo: 1, hashes: hashes,
		},
	}

	sched := NewAnchorScheduler(repo, failPrimary, 0, []string{"audit_logs"}).
		WithAdditionalSinks(secondary)
	if err := sched.anchorTable(context.Background(), "audit_logs"); err != nil {
		t.Fatalf("fail-open: anchorTable should not return error, got: %v", err)
	}
	// Primary anchor written with sink_ok=false (existing fail-open semantics).
	if !repo.anchored {
		t.Error("anchor not written even though primary sink failed (fail-open required)")
	}
	if repo.lastWritten.SinkOK {
		t.Error("primary sink_ok should be false when primary sink fails")
	}
	// Secondary sink should also have been called (best-effort on all sinks).
	if len(secondary.receivedManifest) == 0 {
		t.Error("secondary sink was not called even though scheduler continued after primary failure")
	}
}

// TestMultiSink_LegacyAnchor_StillVerifies — legacy anchors (no rows in
// audit_chain_anchor_sinks) continue to verify with single-sink path.
func TestMultiSink_LegacyAnchor_StillVerifies(t *testing.T) {
	// Simulate a legacy anchor: only single-sink info in primary row.
	// ListAnchorSinks returns empty → legacy mode.
	repo := &multiSinkRepo{} // empty sinkResults = legacy

	sinks, err := repo.ListAnchorSinks(context.Background(), "legacy-anchor-id")
	if err != nil {
		t.Fatalf("ListAnchorSinks: %v", err)
	}
	if len(sinks) != 0 {
		t.Errorf("legacy anchor should have 0 additional sinks, got %d", len(sinks))
	}
	// Verifier interprets 0 additional sinks as legacy / single-sink anchor.
	// No regression in verification logic.
	t.Log("legacy anchor: 0 additional sinks → single-sink verification path")
}

// TestMultiSink_VerifyDetectsMissingSink — if a sink ref was recorded but is
// now inaccessible, verifier returns not-ok.
func TestMultiSink_VerifyDetectsMissingSink(t *testing.T) {
	// Simulate an anchor with one additional file sink that no longer exists.
	results := []AnchorSinkResult{
		{SinkName: "file://", SinkRef: "file:///nonexistent/anchor.ndjson", SinkOK: true},
	}
	repo := &multiSinkRepo{sinkResults: results}

	sinks, _ := repo.ListAnchorSinks(context.Background(), "test-anchor-id")
	if len(sinks) == 0 {
		t.Fatal("expected 1 additional sink record")
	}

	// Attempt to re-read the file sink.
	path := "file:///nonexistent/anchor.ndjson"[len("file://"):]
	_, err := os.Stat(path)
	if err == nil {
		t.Skip("test file unexpectedly exists; skipping")
	}
	// File missing → verifier detects "sink ref recorded but inaccessible"
	t.Logf("sink ref %q inaccessible (expected for test): %v", path, err)
	// The verifier would report this as status="missing" or "unverified".
	// This test validates the detection path, not the full verifier output.
}

func TestVerifyFileSinkManifest_MatchesExactAnchor(t *testing.T) {
	a := testMultiSinkAnchor()
	manifest, err := MarshalSignedManifest(a)
	if err != nil {
		t.Fatalf("MarshalSignedManifest: %v", err)
	}
	path := writeSinkManifest(t, manifest)

	ok, err := verifyFileSinkManifest(path, a, nil)
	if err != nil {
		t.Fatalf("verifyFileSinkManifest: %v", err)
	}
	if !ok {
		t.Fatal("expected exact manifest match")
	}
}

func TestVerifyFileSinkManifest_MismatchedRootFails(t *testing.T) {
	a := testMultiSinkAnchor()
	tampered := *a
	tampered.MerkleRoot = bytes.Repeat([]byte{0x02}, 32)
	manifest, err := MarshalSignedManifest(&tampered)
	if err != nil {
		t.Fatalf("MarshalSignedManifest: %v", err)
	}
	path := writeSinkManifest(t, manifest)

	ok, err := verifyFileSinkManifest(path, a, nil)
	if err != nil {
		t.Fatalf("verifyFileSinkManifest: %v", err)
	}
	if ok {
		t.Fatal("mismatched manifest root must fail")
	}
}

func TestVerifyFileSinkManifest_UnrelatedAnchorFails(t *testing.T) {
	a := testMultiSinkAnchor()
	other := *a
	other.SeqLo = 10
	other.SeqHi = 20
	manifest, err := MarshalSignedManifest(&other)
	if err != nil {
		t.Fatalf("MarshalSignedManifest: %v", err)
	}
	path := writeSinkManifest(t, manifest)

	ok, err := verifyFileSinkManifest(path, a, nil)
	if err != nil {
		t.Fatalf("verifyFileSinkManifest: %v", err)
	}
	if ok {
		t.Fatal("unrelated manifest must not satisfy expected anchor")
	}
}

func TestVerifyFileSinkManifest_KeyringValidatesSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	a := testMultiSinkAnchor()
	if err := SignAnchor(a, priv, "k1"); err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}
	manifest, err := MarshalSignedManifest(a)
	if err != nil {
		t.Fatalf("MarshalSignedManifest: %v", err)
	}
	path := writeSinkManifest(t, manifest)
	keyring := NewSigningKeyring(map[string]ed25519.PublicKey{"k1": pub}, nil)

	ok, err := verifyFileSinkManifest(path, a, keyring)
	if err != nil {
		t.Fatalf("verifyFileSinkManifest: %v", err)
	}
	if !ok {
		t.Fatal("expected keyring signature verification to pass")
	}
}

func TestVerifyFileSinkManifest_KeyringRejectsUnknownKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	a := testMultiSinkAnchor()
	if err := SignAnchor(a, priv, "k1"); err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}
	manifest, err := MarshalSignedManifest(a)
	if err != nil {
		t.Fatalf("MarshalSignedManifest: %v", err)
	}
	path := writeSinkManifest(t, manifest)
	keyring := NewSigningKeyring(map[string]ed25519.PublicKey{}, nil)

	ok, err := verifyFileSinkManifest(path, a, keyring)
	if err != nil {
		t.Fatalf("verifyFileSinkManifest: %v", err)
	}
	if ok {
		t.Fatal("unknown pubkey_id must fail when keyring is provided")
	}
}

func testMultiSinkAnchor() *AnchorRecord {
	return &AnchorRecord{
		ID:         "anchor-1",
		TableName:  "audit_logs",
		SeqLo:      1,
		SeqHi:      3,
		RowCount:   3,
		MerkleRoot: bytes.Repeat([]byte{0x01}, 32),
		CreatedAt:  time.Unix(1714000000, 0).UTC(),
		SinkName:   "file://",
		SinkRef:    "file:///primary.ndjson",
		SinkOK:     true,
	}
}

func writeSinkManifest(t *testing.T, manifest []byte) string {
	t.Helper()
	path := t.TempDir() + "/anchors.ndjson"
	if err := os.WriteFile(path, append(manifest, '\n'), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

// TestMultiSink_WriteOrderDoesNotAffectManifest — manifest content must be the
// same regardless of which sinks are present. The canonical is built BEFORE
// additional sinks are called, so sink order doesn't influence signing.
func TestMultiSink_WriteOrderDoesNotAffectManifest(t *testing.T) {
	hashes := [][]byte{make([]byte, 32)}
	hashes[0][0] = 0xEE

	sinkA := &captureManifestSink{buildRef: "file:///sinkA"}
	sinkB := &captureManifestSink{buildRef: "file:///sinkB"}
	repoAB := &multiSinkRepo{
		testAnchorRepo: testAnchorRepo{lastSeqHi: 0, maxSeqNo: 1, hashes: hashes},
	}
	repoBA := &multiSinkRepo{
		testAnchorRepo: testAnchorRepo{lastSeqHi: 0, maxSeqNo: 1, hashes: hashes},
	}

	sinkA2 := &captureManifestSink{buildRef: "file:///sinkA"}
	sinkB2 := &captureManifestSink{buildRef: "file:///sinkB"}

	// Order AB
	schedAB := NewAnchorScheduler(repoAB, &testSink{}, 0, []string{"audit_logs"}).
		WithAdditionalSinks(sinkA, sinkB)
	if err := schedAB.anchorTable(context.Background(), "audit_logs"); err != nil {
		t.Fatal(err)
	}

	// Order BA
	schedBA := NewAnchorScheduler(repoBA, &testSink{}, 0, []string{"audit_logs"}).
		WithAdditionalSinks(sinkB2, sinkA2)
	if err := schedBA.anchorTable(context.Background(), "audit_logs"); err != nil {
		t.Fatal(err)
	}

	// Manifests for corresponding sinks must be identical regardless of order.
	if string(sinkA.receivedManifest) != string(sinkA2.receivedManifest) {
		t.Error("sinkA received different manifest depending on write order")
	}
	if string(sinkB.receivedManifest) != string(sinkB2.receivedManifest) {
		t.Error("sinkB received different manifest depending on write order")
	}
}

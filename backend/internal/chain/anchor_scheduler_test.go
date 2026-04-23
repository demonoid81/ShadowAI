package chain

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestFileSink_Write_NDJSON — FileSink записывает signed manifest JSON
// через новый двухфазный интерфейс.
func TestFileSink_Write_NDJSON(t *testing.T) {
	tmp := t.TempDir() + "/anchor_test.ndjson"
	sink := NewFileSink(tmp)

	a := &AnchorRecord{
		TableName:  "audit_logs",
		SeqLo:      1,
		SeqHi:      10,
		RowCount:   10,
		MerkleRoot: make([]byte, 32),
	}
	// Phase 1: build ref.
	ref := sink.BuildRef(a)
	if ref != "file://"+tmp {
		t.Errorf("BuildRef = %q, want file://%s", ref, tmp)
	}
	a.SinkRef = ref
	a.SinkName = sink.Name()

	// Phase 2: marshal (no signing for this test).
	manifest, err := MarshalSignedManifest(a)
	if err != nil {
		t.Fatalf("MarshalSignedManifest: %v", err)
	}

	// Phase 3: write.
	if err := sink.Write(context.Background(), manifest, ref); err != nil {
		t.Fatalf("Write: %v", err)
	}

	content, _ := os.ReadFile(tmp)
	line := strings.TrimRight(string(content), "\n")
	if !strings.HasPrefix(line, `{"v":1`) {
		t.Errorf("NDJSON line malformed: %q", line)
	}
	if !strings.Contains(line, `"table":"audit_logs"`) {
		t.Errorf("table field missing: %q", line)
	}
}

// TestAnchorScheduler_NoNewRows_NoOp — если новых chained rows нет,
// anchor не пишется (acceptance criterion #3).
func TestAnchorScheduler_NoNewRows_NoOp(t *testing.T) {
	written := 0
	sink := &testSink{writeFn: func(_ []byte, _ string) error {
		written++
		return nil
	}}
	// lastSeqHi == maxSeqNo → no new rows.
	repo := &testAnchorRepo{lastSeqHi: 10, maxSeqNo: 10}
	sched := NewAnchorScheduler(repo, sink, 0, []string{"audit_logs"})
	if err := sched.anchorTable(context.Background(), "audit_logs"); err != nil {
		t.Fatalf("anchorTable: %v", err)
	}
	if written != 0 {
		t.Errorf("wrote anchor when no new rows existed, written=%d", written)
	}
}

// TestAnchorScheduler_NewRows_WritesAnchor — новые rows → anchor пишется
// с правильным row_count и merkle_root.
func TestAnchorScheduler_NewRows_WritesAnchor(t *testing.T) {
	hashes := [][]byte{
		make([]byte, 32),
		make([]byte, 32),
	}
	hashes[0][0] = 0xAA
	hashes[1][0] = 0xBB

	sink := &testSink{buildRef: "file:///test"}
	repo := &testAnchorRepo{lastSeqHi: 10, maxSeqNo: 12, hashes: hashes}
	sched := NewAnchorScheduler(repo, sink, 0, []string{"audit_logs"})
	if err := sched.anchorTable(context.Background(), "audit_logs"); err != nil {
		t.Fatalf("anchorTable: %v", err)
	}

	if repo.lastWritten == nil {
		t.Fatal("expected anchor written, got nil")
	}
	a := repo.lastWritten
	if a.RowCount != 2 {
		t.Errorf("RowCount = %d, want 2", a.RowCount)
	}
	if a.SeqLo != 11 || a.SeqHi != 12 {
		t.Errorf("range = [%d,%d], want [11,12]", a.SeqLo, a.SeqHi)
	}
	expectedRoot := ComputeMerkleRoot(hashes)
	if !merkleEqual(a.MerkleRoot, expectedRoot) {
		t.Errorf("merkle root mismatch")
	}
	if !repo.anchored {
		t.Error("WriteAnchor not called")
	}
	if !a.SinkOK {
		t.Error("sink_ok=false, want true")
	}
	// Verify manifest was passed to sink (not raw AnchorRecord).
	if a.SinkRef != "file:///test" {
		t.Errorf("SinkRef = %q, want file:///test (BuildRef should have been called)", a.SinkRef)
	}
}

// TestAnchorScheduler_SinkFail_AnchorStillWritten — sink fail не блокирует
// запись anchor'а в PG (fail-open).
func TestAnchorScheduler_SinkFail_AnchorStillWritten(t *testing.T) {
	hashes := [][]byte{make([]byte, 32)}
	sink := &testSink{writeFn: func(_ []byte, _ string) error {
		return fmt.Errorf("simulated sink failure")
	}}
	repo := &testAnchorRepo{lastSeqHi: 0, maxSeqNo: 1, hashes: hashes}
	sched := NewAnchorScheduler(repo, sink, 0, []string{"audit_logs"})
	if err := sched.anchorTable(context.Background(), "audit_logs"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !repo.anchored {
		t.Error("WriteAnchor not called even though sink failed (fail-open required)")
	}
	if repo.lastWritten == nil || repo.lastWritten.SinkOK {
		t.Error("sink_ok should be false when sink fails")
	}
}

// --- test mocks ---

type testAnchorRepo struct {
	lastSeqHi   int64
	maxSeqNo    int64
	hashes      [][]byte
	anchored    bool
	lastWritten *AnchorRecord
}

func (m *testAnchorRepo) LastAnchorSeqHi(_ context.Context, _ string) (int64, error) {
	return m.lastSeqHi, nil
}
func (m *testAnchorRepo) MaxSeqNo(_ context.Context, _ string) (int64, error) {
	return m.maxSeqNo, nil
}
func (m *testAnchorRepo) FetchRowHashes(_ context.Context, _ string, _, _ int64) ([][]byte, error) {
	return m.hashes, nil
}
func (m *testAnchorRepo) WriteAnchor(_ context.Context, a *AnchorRecord) error {
	m.anchored = true
	m.lastWritten = a
	return nil
}

type testSink struct {
	writeFn   func(manifest []byte, ref string) error
	buildRef  string
}

func (s *testSink) Name() string { return "test://" }
func (s *testSink) BuildRef(_ *AnchorRecord) string {
	if s.buildRef != "" {
		return s.buildRef
	}
	return "test://ref"
}
func (s *testSink) Write(_ context.Context, manifest []byte, ref string) error {
	if s.writeFn != nil {
		return s.writeFn(manifest, ref)
	}
	return nil
}

package chain

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestFileSink_Write_NDJSON — FileSink записывает валидный JSON и
// возвращает "file://{path}" как ref.
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
	ref, err := sink.Write(context.Background(), a)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if ref != "file://"+tmp {
		t.Errorf("ref = %q, want file://%s", ref, tmp)
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
	sink := &testSink{writeFn: func(_ *AnchorRecord) (string, error) {
		written++
		return "mock://ref", nil
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

	var written *AnchorRecord
	sink := &testSink{writeFn: func(a *AnchorRecord) (string, error) {
		written = a
		return "file:///test", nil
	}}
	repo := &testAnchorRepo{lastSeqHi: 10, maxSeqNo: 12, hashes: hashes}
	sched := NewAnchorScheduler(repo, sink, 0, []string{"audit_logs"})
	if err := sched.anchorTable(context.Background(), "audit_logs"); err != nil {
		t.Fatalf("anchorTable: %v", err)
	}

	if written == nil {
		t.Fatal("expected anchor written, got nil")
	}
	if written.RowCount != 2 {
		t.Errorf("RowCount = %d, want 2", written.RowCount)
	}
	if written.SeqLo != 11 || written.SeqHi != 12 {
		t.Errorf("range = [%d,%d], want [11,12]", written.SeqLo, written.SeqHi)
	}
	expectedRoot := ComputeMerkleRoot(hashes)
	if !merkleEqual(written.MerkleRoot, expectedRoot) {
		t.Errorf("merkle root mismatch")
	}
	if !repo.anchored {
		t.Error("WriteAnchor not called")
	}
	if !written.SinkOK {
		t.Error("sink_ok=false, want true")
	}
}

// TestAnchorScheduler_SinkFail_AnchorStillWritten — sink fail не блокирует
// запись anchor'а в PG (fail-open).
func TestAnchorScheduler_SinkFail_AnchorStillWritten(t *testing.T) {
	hashes := [][]byte{make([]byte, 32)}
	sink := &testSink{writeFn: func(_ *AnchorRecord) (string, error) {
		return "", fmt.Errorf("simulated sink failure")
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
	writeFn func(*AnchorRecord) (string, error)
}

func (s *testSink) Name() string { return "test://" }
func (s *testSink) Write(_ context.Context, a *AnchorRecord) (string, error) {
	return s.writeFn(a)
}

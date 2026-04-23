package chain

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// FileSink — file:// NDJSON AnchorSink (W3 baseline).
//
// Каждый Write() appends одну JSON строку в файл:
//   {"v":1,"table":"audit_logs","seq_lo":101,"seq_hi":140,
//    "row_count":40,"merkle_root_hex":"...","created_at":"2026-04-23T12:34:56Z"}
//
// Файл создаётся автоматически при первом Write.
// Append operations на POSIX системах атомарны для записей < 4096 байт
// (это держится для наших NDJSON строк).
//
// FileSink безопасен для concurrent writes через mu lock. В production
// anchor scheduler запускается как единственный writer, lock — safety net.
type FileSink struct {
	path string
	mu   sync.Mutex
}

// NewFileSink создаёт FileSink для указанного path.
func NewFileSink(path string) *FileSink {
	return &FileSink{path: path}
}

// ndjsonAnchor — wire shape для file sink. Версионировано (v:1) для
// forward-compat если формат расширится.
type ndjsonAnchor struct {
	V             int    `json:"v"`
	Table         string `json:"table"`
	SeqLo         int64  `json:"seq_lo"`
	SeqHi         int64  `json:"seq_hi"`
	RowCount      int    `json:"row_count"`
	MerkleRootHex string `json:"merkle_root_hex"`
	CreatedAt     string `json:"created_at"`
}

func (f *FileSink) Name() string { return "file://" }

// Write appends anchor как NDJSON line. Returns "file://{path}" as ref.
func (f *FileSink) Write(_ context.Context, a *AnchorRecord) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	payload := ndjsonAnchor{
		V:             1,
		Table:         a.TableName,
		SeqLo:         a.SeqLo,
		SeqHi:         a.SeqHi,
		RowCount:      a.RowCount,
		MerkleRootHex: a.MerkleRootHex(),
		CreatedAt:     a.CreatedAt.UTC().Format(time.RFC3339),
	}
	line, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("file sink: marshal: %w", err)
	}
	line = append(line, '\n')

	fh, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return "", fmt.Errorf("file sink: open %s: %w", f.path, err)
	}
	defer fh.Close()
	if _, err := fh.Write(line); err != nil {
		return "", fmt.Errorf("file sink: write: %w", err)
	}
	return "file://" + f.path, nil
}

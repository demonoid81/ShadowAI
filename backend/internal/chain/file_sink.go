package chain

import (
	"context"
	"fmt"
	"os"
	"sync"
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


func (f *FileSink) Name() string { return "file://" }

// BuildRef returns "file://{path}" as deterministic ref.
func (f *FileSink) BuildRef(_ *AnchorRecord) string {
	return "file://" + f.path
}

// Write appends manifest bytes (one line) to the NDJSON file.
// PR-W4.2: manifest is pre-serialized by scheduler (MarshalSignedManifest).
func (f *FileSink) Write(_ context.Context, manifest []byte, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Ensure manifest ends with newline for NDJSON format.
	line := manifest
	if len(line) == 0 || line[len(line)-1] != '\n' {
		line = append(append([]byte(nil), line...), '\n')
	}

	fh, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("file sink: open %s: %w", f.path, err)
	}
	defer fh.Close()
	if _, err := fh.Write(line); err != nil {
		return fmt.Errorf("file sink: write: %w", err)
	}
	return nil
}

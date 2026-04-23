package chain

import "context"

// AnchorSink публикует signed anchor manifest в external immutable location.
// W3 baseline: file:// (FileSink). W4.2: immudb://.
//
// PR-W4.2 refactor: двухфазный интерфейс.
//   1. BuildRef(a) — возвращает deterministic sink reference ДО signing.
//      Scheduler включает ref в AnchorRecord.SinkRef, затем подписывает
//      canonical (который включает sink_ref).
//   2. Write(ctx, manifest, ref) — пишет pre-serialized signed manifest
//      по deterministic ref. При fail anchor пишется в PG с sink_ok=false.
//
// Порядок в scheduler:
//   a. Merkle root computed.
//   b. BuildRef(a) → a.SinkRef set.
//   c. SignAnchor(a) → signature covers sink_ref.
//   d. MarshalSignedManifest(a) → manifest bytes.
//   e. Write(ctx, manifest, a.SinkRef).
type AnchorSink interface {
	// Name возвращает sink type identifier ("file://", "immudb://", ...).
	Name() string
	// BuildRef returns the deterministic sink reference for this anchor
	// without writing anything. Called before signing so that sink_ref
	// is covered by the Ed25519 signature.
	BuildRef(a *AnchorRecord) string
	// Write stores the signed manifest bytes at the given ref.
	// manifest = MarshalSignedManifest output.
	Write(ctx context.Context, manifest []byte, ref string) error
}

// NoOpSink — заглушка. anchor пишется только в PG без external sink.
type NoOpSink struct{}

func (NoOpSink) Name() string                                              { return "" }
func (NoOpSink) BuildRef(_ *AnchorRecord) string                           { return "" }
func (NoOpSink) Write(_ context.Context, _ []byte, _ string) error         { return nil }

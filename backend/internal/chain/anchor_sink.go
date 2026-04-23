package chain

import "context"

// AnchorSink публикует Merkle anchor в external immutable location.
// W3 baseline: file:// (FileSink). W4+: siem://, immudb://, s3://.
//
// Write возвращает (ref, nil) при успехе; ref — sink-specific reference
// (filepath, block hash, etc.) записывается в audit_chain_anchors.sink_ref.
// При ошибке anchor пишется в PG с sink_ok=false — нет external witness,
// но local PG chain integrity сохраняется.
type AnchorSink interface {
	// Name возвращает sink type identifier ("file://", "siem://", ...).
	// Используется в audit_chain_anchors.sink_name.
	Name() string
	// Write публикует anchor в sink. Returns sink ref or error.
	Write(ctx context.Context, a *AnchorRecord) (ref string, err error)
}

// NoOpSink — заглушка. anchor пишется только в PG без external sink.
// Используется если AUDIT_ANCHOR_SINK не настроен.
type NoOpSink struct{}

func (NoOpSink) Name() string { return "" }
func (NoOpSink) Write(_ context.Context, _ *AnchorRecord) (string, error) {
	return "", nil
}

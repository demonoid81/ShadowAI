package chain

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"time"
)

// AnchorRepoReader — minimal interface used by AnchorScheduler.
// Concrete implementation: *AnchorRepository. Tests use mocks.
type AnchorRepoReader interface {
	LastAnchorSeqHi(ctx context.Context, tableName string) (int64, error)
	MaxSeqNo(ctx context.Context, tableName string) (int64, error)
	FetchRowHashes(ctx context.Context, tableName string, seqLo, seqHi int64) ([][]byte, error)
	WriteAnchor(ctx context.Context, a *AnchorRecord) error
}

// AnchorScheduler — W3 Merkle anchor scheduler. Периодически запускает
// anchorOnce(), которая для каждой configured таблицы:
//   1. Читает last anchor seq_hi.
//   2. Читает max(seq_no) из chained rows.
//   3. Если новых rows нет — no-op (не пишет пустой anchor).
//   4. Иначе: получает row_hashes, вычисляет Merkle root, пишет AnchorRecord
//      в audit_chain_anchors + вызывает AnchorSink.Write.
//
// Sink fail-open: если sink.Write fail'ится, anchor пишется в PG с
// sink_ok=false. Local chain integrity сохраняется; нет external witness.
// Оператор видит это через sink_ok column и метрику.
//
// Tables — чёткий список таблиц для anchor'ования. Scheduler не guesses.
type AnchorScheduler struct {
	repo     AnchorRepoReader
	sink     AnchorSink
	interval time.Duration
	tables   []string
	// W4.1: optional Ed25519 signing.
	signingKey ed25519.PrivateKey
	pubKeyID   string
	// selfVerify: if true, verify signature immediately after signing
	// (uses public key derived from private key). Catches misconfiguration early.
	selfVerify bool
}

// NewAnchorScheduler создаёт scheduler. Если interval == 0 — Run() немедленно
// возвращает. Если sink == nil — используется NoOpSink.
func NewAnchorScheduler(repo AnchorRepoReader, sink AnchorSink, interval time.Duration, tables []string) *AnchorScheduler {
	if sink == nil {
		sink = NoOpSink{}
	}
	return &AnchorScheduler{
		repo:     repo,
		sink:     sink,
		interval: interval,
		tables:   tables,
	}
}

// WithSigning configures Ed25519 signing for each anchor manifest.
// pubKeyID is stored in anchor rows; selfVerify re-verifies immediately
// after signing using the derived public key.
func (s *AnchorScheduler) WithSigning(privKey ed25519.PrivateKey, pubKeyID string, selfVerify bool) *AnchorScheduler {
	s.signingKey = privKey
	s.pubKeyID = pubKeyID
	s.selfVerify = selfVerify
	return s
}

// Run запускает scheduler. Блокирует до ctx.Done(). Первый anchor run
// выполняется сразу при запуске, затем по интервалу.
func (s *AnchorScheduler) Run(ctx context.Context) {
	if s.interval == 0 {
		return
	}
	log.Printf("anchor scheduler: starting, interval=%s tables=%v sink=%s",
		s.interval, s.tables, s.sink.Name())
	s.anchorOnce(ctx)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.anchorOnce(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// anchorOnce выполняет один anchor run для всех tables.
func (s *AnchorScheduler) anchorOnce(ctx context.Context) {
	for _, table := range s.tables {
		if err := s.anchorTable(ctx, table); err != nil {
			log.Printf("anchor scheduler: table=%s err=%v", table, err)
		}
	}
}

// anchorTable — anchor run для одной таблицы.
func (s *AnchorScheduler) anchorTable(ctx context.Context, tableName string) error {
	lastSeqHi, err := s.repo.LastAnchorSeqHi(ctx, tableName)
	if err != nil {
		return fmt.Errorf("anchor %s: last seq_hi: %w", tableName, err)
	}
	maxSeq, err := s.repo.MaxSeqNo(ctx, tableName)
	if err != nil {
		return fmt.Errorf("anchor %s: max seq_no: %w", tableName, err)
	}

	// No new chained rows since last anchor — skip (acceptance criterion #3).
	if maxSeq <= lastSeqHi {
		return nil
	}

	// Fetch row_hashes for new rows.
	hashes, err := s.repo.FetchRowHashes(ctx, tableName, lastSeqHi, maxSeq)
	if err != nil {
		return fmt.Errorf("anchor %s: fetch hashes: %w", tableName, err)
	}
	if len(hashes) == 0 {
		return nil // shouldn't happen given maxSeq > lastSeqHi, but defensive
	}

	// Compute Merkle root.
	root := ComputeMerkleRoot(hashes)
	if root == nil {
		return fmt.Errorf("anchor %s: nil merkle root (unexpected)", tableName)
	}

	// Build anchor record.
	a := &AnchorRecord{
		TableName:  tableName,
		SeqLo:      lastSeqHi + 1,
		SeqHi:      maxSeq,
		RowCount:   len(hashes),
		MerkleRoot: root,
		CreatedAt:  time.Now().UTC(),
		SinkName:   s.sink.Name(),
	}

	// Write to sink (fail-open: on error, still write to PG with sink_ok=false).
	ref, sinkErr := s.sink.Write(ctx, a)
	a.SinkRef = ref
	a.SinkOK = sinkErr == nil
	if sinkErr != nil {
		log.Printf("anchor scheduler: table=%s sink write failed (anchor still written to PG): %v",
			tableName, sinkErr)
	}

	// PR-W4.1: sign manifest AFTER sink write (canonical includes sink_ref).
	if len(s.signingKey) > 0 && s.pubKeyID != "" {
		if err := SignAnchor(a, s.signingKey, s.pubKeyID); err != nil {
			return fmt.Errorf("anchor %s: sign: %w", tableName, err)
		}
		// Self-verify: catch misconfiguration before persisting to DB.
		if s.selfVerify {
			pubKey := s.signingKey.Public().(ed25519.PublicKey)
			if !VerifyAnchorSignature(a, pubKey) {
				return fmt.Errorf("anchor %s: self-verify failed (signing misconfiguration)", tableName)
			}
		}
	}

	// Write to audit_chain_anchors.
	if err := s.repo.WriteAnchor(ctx, a); err != nil {
		return fmt.Errorf("anchor %s: write record: %w", tableName, err)
	}

	log.Printf("anchor scheduler: table=%s seq=[%d,%d] rows=%d root=%x sink_ok=%v ref=%s",
		tableName, a.SeqLo, a.SeqHi, a.RowCount, root[:8], a.SinkOK, a.SinkRef)
	return nil
}

package chain

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// AnchorRecord — одна запись в audit_chain_anchors. Содержит Merkle root
// над row_hash'ами диапазона [SeqLo, SeqHi] для одной таблицы.
type AnchorRecord struct {
	ID          string
	TableName   string
	SeqLo       int64
	SeqHi       int64
	RowCount    int
	MerkleRoot  []byte
	CreatedAt   time.Time
	SinkName    string
	SinkRef     string
	SinkOK      bool
}

// MerkleRootHex возвращает Merkle root в hex для NDJSON serialization.
func (a *AnchorRecord) MerkleRootHex() string {
	return hex.EncodeToString(a.MerkleRoot)
}

// AnchorRepository читает/пишет записи в audit_chain_anchors.
type AnchorRepository struct {
	db *sql.DB
}

// NewAnchorRepository создаёт AnchorRepository с существующим DB connection.
func NewAnchorRepository(db *sql.DB) *AnchorRepository {
	return &AnchorRepository{db: db}
}

// LastAnchorSeqHi возвращает максимальный seq_hi для таблицы, или 0
// если anchor'ов ещё нет. Используется scheduler'ом для определения
// диапазона новых rows.
func (r *AnchorRepository) LastAnchorSeqHi(ctx context.Context, tableName string) (int64, error) {
	var seqHi int64
	err := r.db.QueryRowContext(ctx,
		`SELECT coalesce(max(anchor_seq_hi), 0) FROM audit_chain_anchors WHERE table_name = $1`,
		tableName).Scan(&seqHi)
	if err != nil {
		return 0, fmt.Errorf("anchor: last seq_hi for %s: %w", tableName, err)
	}
	return seqHi, nil
}

// MaxSeqNo возвращает максимальный seq_no из chained rows таблицы.
// Используется scheduler'ом для определения SeqHi нового anchor'а.
func (r *AnchorRepository) MaxSeqNo(ctx context.Context, tableName string) (int64, error) {
	var maxSeq int64
	err := r.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT coalesce(max(seq_no), 0) FROM %s WHERE seq_no IS NOT NULL`, tableName),
	).Scan(&maxSeq)
	if err != nil {
		return 0, fmt.Errorf("anchor: max seq_no for %s: %w", tableName, err)
	}
	return maxSeq, nil
}

// FetchRowHashes возвращает row_hash'и строк с seq_no в диапазоне (seqLo, seqHi],
// упорядоченные по seq_no. Используется для вычисления Merkle root.
func (r *AnchorRepository) FetchRowHashes(ctx context.Context, tableName string, seqLo, seqHi int64) ([][]byte, error) {
	rows, err := r.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT row_hash FROM %s
		             WHERE seq_no > $1 AND seq_no <= $2 AND row_hash IS NOT NULL
		             ORDER BY seq_no`, tableName),
		seqLo, seqHi)
	if err != nil {
		return nil, fmt.Errorf("anchor: fetch hashes for %s (%d,%d]: %w", tableName, seqLo, seqHi, err)
	}
	defer rows.Close()
	var hashes [][]byte
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("anchor: scan hash: %w", err)
		}
		hashes = append(hashes, h)
	}
	return hashes, rows.Err()
}

// WriteAnchor вставляет новую anchor запись в audit_chain_anchors.
func (r *AnchorRepository) WriteAnchor(ctx context.Context, a *AnchorRecord) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO audit_chain_anchors
		 (table_name, anchor_seq_lo, anchor_seq_hi, row_count, merkle_root, created_at, sink_name, sink_ref, sink_ok)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		a.TableName, a.SeqLo, a.SeqHi, a.RowCount, a.MerkleRoot,
		a.CreatedAt, a.SinkName, a.SinkRef, a.SinkOK)
	if err != nil {
		return fmt.Errorf("anchor: write for %s: %w", a.TableName, err)
	}
	return nil
}

// ListAnchors возвращает anchor записи для таблицы в порядке seq_lo ASC.
// Используется verifier'ом для --include-anchors.
func (r *AnchorRepository) ListAnchors(ctx context.Context, tableName string) ([]AnchorRecord, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, table_name, anchor_seq_lo, anchor_seq_hi, row_count, merkle_root,
		        created_at, sink_name, sink_ref, sink_ok
		 FROM audit_chain_anchors WHERE table_name = $1
		 ORDER BY anchor_seq_lo`, tableName)
	if err != nil {
		return nil, fmt.Errorf("anchor: list for %s: %w", tableName, err)
	}
	defer rows.Close()
	var records []AnchorRecord
	for rows.Next() {
		var a AnchorRecord
		if err := rows.Scan(&a.ID, &a.TableName, &a.SeqLo, &a.SeqHi, &a.RowCount,
			&a.MerkleRoot, &a.CreatedAt, &a.SinkName, &a.SinkRef, &a.SinkOK); err != nil {
			return nil, fmt.Errorf("anchor: scan: %w", err)
		}
		records = append(records, a)
	}
	return records, rows.Err()
}

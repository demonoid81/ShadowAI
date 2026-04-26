package chain

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// AnchorRecord — одна запись в audit_chain_anchors. Содержит Merkle root
// над row_hash'ами диапазона [SeqLo, SeqHi] для одной таблицы.
//
// PR-W4.1: добавлены PubKeyID + Signature для Ed25519 signed manifests.
// NULL Signature = unsigned anchor (pre-W4.1 row или signing disabled).
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
	// W4.1 signature fields. Empty = unsigned.
	PubKeyID  string
	Signature []byte
}

// MerkleRootHex возвращает Merkle root в hex для NDJSON serialization.
func (a *AnchorRecord) MerkleRootHex() string {
	return hex.EncodeToString(a.MerkleRoot)
}

// chainTables is the exhaustive allowlist of tables that participate in the
// HMAC chain. Used to validate tableName before fmt.Sprintf into SQL to
// prevent accidental injection if the method is called from non-CLI paths.
var chainTables = map[string]bool{
	"audit_logs":        true,
	"admin_event_logs":  true,
	"legal_hold_events": true,
	"audit_purge_runs":  true,
}

// validateChainTable returns an error if tableName is not in the allowlist.
func validateChainTable(tableName string) error {
	if !chainTables[tableName] {
		return fmt.Errorf("unknown chain table %q: must be audit_logs|admin_event_logs|legal_hold_events|audit_purge_runs", tableName)
	}
	return nil
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
// PR-W4.1: включает pubkey_id + signature если установлены.
func (r *AnchorRepository) WriteAnchor(ctx context.Context, a *AnchorRecord) error {
	var pubKeyID any
	var sig any
	if a.PubKeyID != "" {
		pubKeyID = a.PubKeyID
	}
	if len(a.Signature) > 0 {
		sig = a.Signature
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO audit_chain_anchors
		 (table_name, anchor_seq_lo, anchor_seq_hi, row_count, merkle_root, created_at, sink_name, sink_ref, sink_ok, pubkey_id, signature)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		a.TableName, a.SeqLo, a.SeqHi, a.RowCount, a.MerkleRoot,
		a.CreatedAt, a.SinkName, a.SinkRef, a.SinkOK, pubKeyID, sig)
	if err != nil {
		return fmt.Errorf("anchor: write for %s: %w", a.TableName, err)
	}
	return nil
}

// ChainInventoryRow — hash digest row for W5 evidence bundle chain_inventory.jsonl.
// Contains seq_no + row_hash only; no canonical row payload.
// See evidencebundle.ChainInventoryLine for the serialization format.
type ChainInventoryRow struct {
	SeqNo      int64
	RowIDHash  string // hex(SHA256(row_id)) — stable identifier, no PII
	RowHashHex string // hex of stored HMAC chain hash
}

// FetchChainInventory returns ChainInventoryRow entries for all chained rows
// in tableName, ordered by seq_no. Supports audit_logs, admin_event_logs,
// legal_hold_events, audit_purge_runs — any table with (id, seq_no, row_hash).
//
// This is a digest-only export: it does NOT include canonical row content or
// AUDIT_CHAIN_SECRET and therefore cannot prove HMAC chain correctness offline.
// It enables gap analysis and anchor Merkle cross-referencing only.
//
// Returns an error for any tableName not in the chain table allowlist.
func (r *AnchorRepository) FetchChainInventory(ctx context.Context, tableName string) ([]ChainInventoryRow, error) {
	if err := validateChainTable(tableName); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT id::text, seq_no, row_hash FROM %s
		             WHERE seq_no IS NOT NULL AND row_hash IS NOT NULL
		             ORDER BY seq_no`, tableName))
	if err != nil {
		return nil, fmt.Errorf("chain inventory %s: query: %w", tableName, err)
	}
	defer rows.Close()
	var result []ChainInventoryRow
	for rows.Next() {
		var rowID string
		var seqNo int64
		var rowHash []byte
		if err := rows.Scan(&rowID, &seqNo, &rowHash); err != nil {
			return nil, fmt.Errorf("chain inventory %s: scan: %w", tableName, err)
		}
		h := sha256.Sum256([]byte(rowID))
		result = append(result, ChainInventoryRow{
			SeqNo:      seqNo,
			RowIDHash:  hex.EncodeToString(h[:]),
			RowHashHex: hex.EncodeToString(rowHash),
		})
	}
	return result, rows.Err()
}

// FetchChainInventoryForOrgAnchors returns the full digest inventory for anchor ranges
// that contain at least one row belonging to orgID (PR-T2.4 Option A per RFC D4).
//
// Per-tenant export: we export ALL row hashes in intersecting anchor ranges —
// including other-org rows — so the verifier can recompute Merkle roots.
// The README bundle disclaimer explains why cross-tenant hashes are present.
// Returns (inventory, intersectingAnchors, error).
func (r *AnchorRepository) FetchChainInventoryForOrgAnchors(ctx context.Context, tableName, orgID string) ([]ChainInventoryRow, []AnchorRecord, error) {
	if err := validateChainTable(tableName); err != nil {
		return nil, nil, err
	}
	// Fetch anchors that contain at least one org row (by seq_no range).
	//nolint:gosec // tableName from allowlist
	orgSeqRows, err := r.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT seq_no FROM %s WHERE org_id = $1 AND seq_no IS NOT NULL`, tableName),
		orgID)
	if err != nil {
		return nil, nil, fmt.Errorf("chain inventory org seq: %w", err)
	}
	defer orgSeqRows.Close()
	var orgSeqNos []int64
	for orgSeqRows.Next() {
		var s int64
		if err := orgSeqRows.Scan(&s); err != nil {
			return nil, nil, fmt.Errorf("chain inventory org seq scan: %w", err)
		}
		orgSeqNos = append(orgSeqNos, s)
	}
	if err := orgSeqRows.Err(); err != nil {
		return nil, nil, err
	}
	if len(orgSeqNos) == 0 {
		return nil, nil, nil // org has no chained rows in this table
	}

	// Find anchors whose [SeqLo, SeqHi] range intersects any org seq_no.
	allAnchors, err := r.ListAnchors(ctx, tableName)
	if err != nil {
		return nil, nil, err
	}
	seqSet := make(map[int64]struct{}, len(orgSeqNos))
	for _, s := range orgSeqNos {
		seqSet[s] = struct{}{}
	}
	var intersecting []AnchorRecord
	for _, a := range allAnchors {
		for s := a.SeqLo; s <= a.SeqHi; s++ {
			if _, ok := seqSet[s]; ok {
				intersecting = append(intersecting, a)
				break
			}
		}
	}
	if len(intersecting) == 0 {
		return nil, nil, nil
	}

	// Fetch rows per-anchor-range, not a single merged span.
	// RFC D4 Option A: full digest inventory for *intersecting* anchor ranges only —
	// not for gaps between them. Dedup by seq_no in case anchor ranges overlap.
	seen := make(map[int64]struct{})
	var result []ChainInventoryRow
	for _, a := range intersecting {
		//nolint:gosec // tableName from allowlist
		invRows, err := r.db.QueryContext(ctx,
			fmt.Sprintf(`SELECT id::text, seq_no, row_hash FROM %s
			             WHERE seq_no >= $1 AND seq_no <= $2
			             ORDER BY seq_no`, tableName),
			a.SeqLo, a.SeqHi)
		if err != nil {
			return nil, nil, fmt.Errorf("chain inventory anchor [%d,%d]: %w", a.SeqLo, a.SeqHi, err)
		}
		for invRows.Next() {
			var rowID string
			var seqNo int64
			var rowHash []byte
			if err := invRows.Scan(&rowID, &seqNo, &rowHash); err != nil {
				invRows.Close()
				return nil, nil, fmt.Errorf("chain inventory anchor scan: %w", err)
			}
			if _, dup := seen[seqNo]; dup {
				continue
			}
			seen[seqNo] = struct{}{}
			h := sha256.Sum256([]byte(rowID))
			result = append(result, ChainInventoryRow{
				SeqNo:      seqNo,
				RowIDHash:  hex.EncodeToString(h[:]),
				RowHashHex: hex.EncodeToString(rowHash),
			})
		}
		if err := invRows.Err(); err != nil {
			invRows.Close()
			return nil, nil, fmt.Errorf("chain inventory anchor rows: %w", err)
		}
		invRows.Close()
	}
	return result, intersecting, nil
}

// ListAnchors возвращает anchor записи для таблицы в порядке seq_lo ASC.
// Используется verifier'ом для --include-anchors.
func (r *AnchorRepository) ListAnchors(ctx context.Context, tableName string) ([]AnchorRecord, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, table_name, anchor_seq_lo, anchor_seq_hi, row_count, merkle_root,
		        created_at, sink_name, sink_ref, sink_ok,
		        coalesce(pubkey_id, ''), signature
		 FROM audit_chain_anchors WHERE table_name = $1
		 ORDER BY anchor_seq_lo`, tableName)
	if err != nil {
		return nil, fmt.Errorf("anchor: list for %s: %w", tableName, err)
	}
	defer rows.Close()
	var records []AnchorRecord
	for rows.Next() {
		var a AnchorRecord
		var sig []byte // nullable BYTEA → nil if NULL
		if err := rows.Scan(&a.ID, &a.TableName, &a.SeqLo, &a.SeqHi, &a.RowCount,
			&a.MerkleRoot, &a.CreatedAt, &a.SinkName, &a.SinkRef, &a.SinkOK,
			&a.PubKeyID, &sig); err != nil {
			return nil, fmt.Errorf("anchor: scan: %w", err)
		}
		a.Signature = sig
		records = append(records, a)
	}
	return records, rows.Err()
}

// TenantAnchorRow is a row fetched for Merkle proof generation.
type TenantAnchorRow struct {
	SeqNo      int64
	RowIDHash  string // hex(SHA256(row_id))
	RowHashHex string // hex of stored row_hash
	IsTenant   bool   // belongs to the export's org
}

// GenerateTenantMerkleProofs generates Merkle inclusion proofs for all rows
// belonging to orgID in intersecting anchor ranges (T3/W6).
//
// For each anchor whose [SeqLo, SeqHi] range contains at least one org row:
//  1. Fetches ALL rows in the range (full set needed to rebuild the Merkle tree).
//  2. Identifies org rows by querying org_id.
//  3. Generates a Merkle inclusion proof for each org row.
//
// Returns:
//   - tenantRows: org rows only (tenant_chain_hashes.jsonl content)
//   - proofs:     per-row inclusion proofs (merkle_proofs.jsonl content)
func (r *AnchorRepository) GenerateTenantMerkleProofs(ctx context.Context, tableName, orgID string) (
	tenantRows []TenantAnchorRow,
	proofs []TenantAnchorProof,
	err error,
) {
	if err := validateChainTable(tableName); err != nil {
		return nil, nil, err
	}

	// Find org row seq_nos.
	//nolint:gosec // tableName from allowlist
	orgSeqRows, err := r.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT id::text, seq_no FROM %s WHERE org_id = $1 AND seq_no IS NOT NULL ORDER BY seq_no`, tableName),
		orgID)
	if err != nil {
		return nil, nil, fmt.Errorf("tenant proofs org seqs: %w", err)
	}
	defer orgSeqRows.Close()
	type orgSeqEntry struct{ id string; seqNo int64 }
	var orgSeqs []orgSeqEntry
	for orgSeqRows.Next() {
		var e orgSeqEntry
		if err := orgSeqRows.Scan(&e.id, &e.seqNo); err != nil {
			return nil, nil, fmt.Errorf("tenant proofs org seq scan: %w", err)
		}
		orgSeqs = append(orgSeqs, e)
	}
	if err := orgSeqRows.Err(); err != nil {
		return nil, nil, err
	}
	if len(orgSeqs) == 0 {
		return nil, nil, nil
	}

	// Build set for quick lookup.
	orgSeqSet := make(map[int64]string, len(orgSeqs)) // seqNo → row_id
	for _, e := range orgSeqs {
		orgSeqSet[e.seqNo] = e.id
	}

	// Get intersecting anchors.
	allAnchors, err := r.ListAnchors(ctx, tableName)
	if err != nil {
		return nil, nil, err
	}
	var intersecting []AnchorRecord
	for _, a := range allAnchors {
		for s := a.SeqLo; s <= a.SeqHi; s++ {
			if _, ok := orgSeqSet[s]; ok {
				intersecting = append(intersecting, a)
				break
			}
		}
	}
	if len(intersecting) == 0 {
		return nil, nil, nil
	}

	// For each intersecting anchor: build full leaf set + generate proofs.
	for _, anchor := range intersecting {
		//nolint:gosec
		rangeRows, rangeErr := r.db.QueryContext(ctx,
			fmt.Sprintf(`SELECT id::text, seq_no, row_hash FROM %s
			             WHERE seq_no >= $1 AND seq_no <= $2
			             ORDER BY seq_no`, tableName),
			anchor.SeqLo, anchor.SeqHi)
		if rangeErr != nil {
			return nil, nil, fmt.Errorf("tenant proofs range query: %w", rangeErr)
		}

		type rangeEntry struct {
			rowID      string
			seqNo      int64
			rowHash    []byte
		}
		var entries []rangeEntry
		for rangeRows.Next() {
			var e rangeEntry
			if err := rangeRows.Scan(&e.rowID, &e.seqNo, &e.rowHash); err != nil {
				rangeRows.Close()
				return nil, nil, fmt.Errorf("tenant proofs range scan: %w", err)
			}
			entries = append(entries, e)
		}
		if rowsErr := rangeRows.Err(); rowsErr != nil {
			rangeRows.Close()
			return nil, nil, rowsErr
		}
		rangeRows.Close()

		if len(entries) == 0 {
			continue
		}

		// Build leaf hash array for Merkle tree (same order as stored).
		leafHashes := make([][]byte, len(entries))
		for i, e := range entries {
			leafHashes[i] = e.rowHash
		}

		rootHex := anchor.MerkleRootHex()

		for leafIdx, e := range entries {
			if _, isTenant := orgSeqSet[e.seqNo]; !isTenant {
				continue
			}
			// Generate proof for this tenant row.
			siblingProof, proofErr := GenerateMerkleProof(leafHashes, leafIdx)
			if proofErr != nil {
				return nil, nil, fmt.Errorf("tenant proofs generate: %w", proofErr)
			}
			rowIDHash := rowIDHashHex(e.rowID)
			rowHashHex := hex.EncodeToString(e.rowHash)

			tenantRows = append(tenantRows, TenantAnchorRow{
				SeqNo:      e.seqNo,
				RowIDHash:  rowIDHash,
				RowHashHex: rowHashHex,
				IsTenant:   true,
			})
			proofs = append(proofs, TenantAnchorProof{
				Table:       tableName,
				SeqNo:       e.seqNo,
				AnchorSeqLo: anchor.SeqLo,
				AnchorSeqHi: anchor.SeqHi,
				LeafHashHex: rowHashHex,
				Siblings:    siblingProof,
				RootHex:     rootHex,
			})
		}
	}
	return tenantRows, proofs, nil
}

// TenantAnchorProof is one Merkle inclusion proof for a tenant row.
type TenantAnchorProof struct {
	Table       string
	SeqNo       int64
	AnchorSeqLo int64
	AnchorSeqHi int64
	LeafHashHex string
	Siblings    []MerkleProofSibling
	RootHex     string
}

// rowIDHashHex returns hex(SHA256(rowID)).
func rowIDHashHex(rowID string) string {
	h := sha256.Sum256([]byte(rowID))
	return hex.EncodeToString(h[:])
}

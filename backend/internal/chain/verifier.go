package chain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// VerifyResult — итог верификации одной таблицы.
type VerifyResult struct {
	Table    string
	RowCount int          // total chained rows scanned
	Gaps     []int64      // seq_no значения которые пропущены
	Breaks   []ChainBreak // rows где hash не совпадает
	OK       bool         // true если Gaps и Breaks пусты
	Duration time.Duration
}

// ChainBreak — одна строка с несовпадающим hash'ом.
type ChainBreak struct {
	SeqNo    int64
	RowID    string
	Expected []byte // что должно быть по chain
	Actual   []byte // что хранится в таблице
}

// AuditRow — минимальный read model для chain verification.
type AuditRow struct {
	ID               string
	UserID           string
	Model            string
	Provider         string
	Endpoint         string
	StatusCode       int
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	CostUSD          float64
	PIIDetected      bool
	PIITypes         []string
	PolicyAction     string
	Outcome          string
	FallbackReason   string
	UsageSource      string
	CreatedAt        time.Time
	SeqNo            int64
	RowHash          []byte
}

// AdminEventRow — минимальный read model для admin_event_logs verification.
type AdminEventRow struct {
	ID          string
	ActorUserID string
	Action      string
	Resource    string
	TargetID    string
	Path        string
	Method      string
	StatusCode  int
	Success     bool
	CreatedAt   time.Time
	SeqNo       int64
	RowHash     []byte
}

// LegalHoldEventRow — minimal read model for legal_hold_events.
type LegalHoldEventRow struct {
	ID        string
	HoldID    string
	Action    string
	NewStatus string
	ActorID   string
	CreatedAt time.Time
	SeqNo     int64
	RowHash   []byte
}

// VerifyAuditLogs верифицирует chain integrity для audit_logs.
// Сканирует только rows с non-NULL seq_no (chained rows).
// secret — AUDIT_CHAIN_SECRET.
func VerifyAuditLogs(ctx context.Context, db *sql.DB, secret []byte) (VerifyResult, error) {
	start := time.Now()
	res := VerifyResult{Table: "audit_logs"}

	rows, err := db.QueryContext(ctx,
		`SELECT id, coalesce(user_id::text,''), coalesce(model,''),
		        coalesce(provider,''), coalesce(endpoint,''), status_code,
		        coalesce(prompt_tokens,0), coalesce(completion_tokens,0),
		        coalesce(total_tokens,0), coalesce(cost_usd,0),
		        coalesce(pii_detected,false), coalesce(pii_types,'{}'),
		        coalesce(policy_action,''), coalesce(outcome,''),
		        coalesce(fallback_reason,''), coalesce(usage_source,''),
		        created_at, seq_no, row_hash,
		        coalesce(canonical_version,'v1'),
		        coalesce(org_id::text,'00000000-0000-0000-0000-000000000001')
		 FROM audit_logs
		 WHERE seq_no IS NOT NULL AND row_hash IS NOT NULL
		 ORDER BY seq_no`)
	if err != nil {
		return res, fmt.Errorf("verify audit_logs: query: %w", err)
	}
	defer rows.Close()

	var prevHash []byte
	var prevSeqNo int64

	for rows.Next() {
		var r AuditRow
		var piiTypes []string
		var canonVer, orgID string
		if err := rows.Scan(
			&r.ID, &r.UserID, &r.Model, &r.Provider, &r.Endpoint,
			&r.StatusCode, &r.PromptTokens, &r.CompletionTokens, &r.TotalTokens,
			&r.CostUSD, &r.PIIDetected, pqArrayScan(&piiTypes),
			&r.PolicyAction, &r.Outcome, &r.FallbackReason, &r.UsageSource,
			&r.CreatedAt, &r.SeqNo, &r.RowHash,
			&canonVer, &orgID,
		); err != nil {
			return res, fmt.Errorf("verify audit_logs: scan: %w", err)
		}
		r.PIITypes = piiTypes
		res.RowCount++

		// Gap detection.
		if res.RowCount > 1 && r.SeqNo != prevSeqNo+1 {
			for gap := prevSeqNo + 1; gap < r.SeqNo; gap++ {
				res.Gaps = append(res.Gaps, gap)
			}
		}

		// Chain break detection — use v1 or v2 canonical based on stored version.
		var canonical string
		if canonVer == "v2" {
			canonical = CanonicalAuditLogV2(
				r.ID, r.UserID, r.Model, r.Provider, r.Endpoint,
				r.StatusCode, r.PromptTokens, r.CompletionTokens, r.TotalTokens,
				CostMicrocents(r.CostUSD),
				r.PIIDetected, r.PIITypes,
				r.PolicyAction, r.Outcome, r.FallbackReason, r.UsageSource,
				r.CreatedAt.UTC().Unix(), orgID,
			)
		} else {
			canonical = CanonicalAuditLog(
				r.ID, r.UserID, r.Model, r.Provider, r.Endpoint,
				r.StatusCode, r.PromptTokens, r.CompletionTokens, r.TotalTokens,
				CostMicrocents(r.CostUSD),
				r.PIIDetected, r.PIITypes,
				r.PolicyAction, r.Outcome, r.FallbackReason, r.UsageSource,
				r.CreatedAt.UTC().Unix(),
			)
		}
		if !Verify(prevHash, canonical, secret, r.RowHash) {
			res.Breaks = append(res.Breaks, ChainBreak{
				SeqNo: r.SeqNo, RowID: r.ID,
				Actual: r.RowHash,
			})
		}

		prevHash = r.RowHash
		prevSeqNo = r.SeqNo
	}
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("verify audit_logs: rows: %w", err)
	}
	res.OK = len(res.Gaps) == 0 && len(res.Breaks) == 0
	res.Duration = time.Since(start)
	return res, nil
}

// VerifyAdminEventLogs верифицирует admin_event_logs.
// Enterprise table; core build can use this if chain was enabled.
func VerifyAdminEventLogs(ctx context.Context, db *sql.DB, secret []byte) (VerifyResult, error) {
	start := time.Now()
	res := VerifyResult{Table: "admin_event_logs"}

	rows, err := db.QueryContext(ctx,
		`SELECT id, coalesce(actor_user_id::text,''), action, resource,
		        coalesce(target_id,''), path, method, status_code, success,
		        created_at, seq_no, row_hash,
		        coalesce(canonical_version,'v1'),
		        coalesce(org_id::text,'00000000-0000-0000-0000-000000000001'),
		        coalesce(source_org_id::text,''),
		        coalesce(target_org_id::text,'')
		 FROM admin_event_logs
		 WHERE seq_no IS NOT NULL AND row_hash IS NOT NULL
		 ORDER BY seq_no`)
	if err != nil {
		return res, fmt.Errorf("verify admin_event_logs: query: %w", err)
	}
	defer rows.Close()

	var prevHash []byte
	var prevSeqNo int64

	for rows.Next() {
		var r AdminEventRow
		var canonVer, orgID, sourceOrgID, targetOrgID string
		if err := rows.Scan(
			&r.ID, &r.ActorUserID, &r.Action, &r.Resource,
			&r.TargetID, &r.Path, &r.Method, &r.StatusCode, &r.Success,
			&r.CreatedAt, &r.SeqNo, &r.RowHash,
			&canonVer, &orgID, &sourceOrgID, &targetOrgID,
		); err != nil {
			return res, fmt.Errorf("verify admin_event_logs: scan: %w", err)
		}
		res.RowCount++

		if res.RowCount > 1 && r.SeqNo != prevSeqNo+1 {
			for gap := prevSeqNo + 1; gap < r.SeqNo; gap++ {
				res.Gaps = append(res.Gaps, gap)
			}
		}

		var canonical string
		if canonVer == "v2" {
			canonical = CanonicalAdminEventLogV2(
				r.ID, r.ActorUserID, r.Action, r.Resource, r.TargetID,
				r.Path, r.Method, r.StatusCode, r.Success,
				r.CreatedAt.UTC().Unix(),
				orgID, sourceOrgID, targetOrgID,
			)
		} else {
			canonical = CanonicalAdminEventLog(
				r.ID, r.ActorUserID, r.Action, r.Resource, r.TargetID,
				r.Path, r.Method, r.StatusCode, r.Success,
				r.CreatedAt.UTC().Unix(),
			)
		}
		if !Verify(prevHash, canonical, secret, r.RowHash) {
			res.Breaks = append(res.Breaks, ChainBreak{
				SeqNo: r.SeqNo, RowID: r.ID, Actual: r.RowHash,
			})
		}

		prevHash = r.RowHash
		prevSeqNo = r.SeqNo
	}
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("verify admin_event_logs: rows: %w", err)
	}
	res.OK = len(res.Gaps) == 0 && len(res.Breaks) == 0
	res.Duration = time.Since(start)
	return res, nil
}

// VerifyLegalHoldEvents верифицирует legal_hold_events.
func VerifyLegalHoldEvents(ctx context.Context, db *sql.DB, secret []byte) (VerifyResult, error) {
	start := time.Now()
	res := VerifyResult{Table: "legal_hold_events"}

	rows, err := db.QueryContext(ctx,
		`SELECT id, hold_id::text, action, new_status,
		        coalesce(actor_id::text,''), created_at, seq_no, row_hash
		 FROM legal_hold_events
		 WHERE seq_no IS NOT NULL AND row_hash IS NOT NULL
		 ORDER BY seq_no`)
	if err != nil {
		return res, fmt.Errorf("verify legal_hold_events: query: %w", err)
	}
	defer rows.Close()

	var prevHash []byte
	var prevSeqNo int64

	for rows.Next() {
		var r LegalHoldEventRow
		if err := rows.Scan(
			&r.ID, &r.HoldID, &r.Action, &r.NewStatus,
			&r.ActorID, &r.CreatedAt, &r.SeqNo, &r.RowHash,
		); err != nil {
			return res, fmt.Errorf("verify legal_hold_events: scan: %w", err)
		}
		res.RowCount++

		if res.RowCount > 1 && r.SeqNo != prevSeqNo+1 {
			for gap := prevSeqNo + 1; gap < r.SeqNo; gap++ {
				res.Gaps = append(res.Gaps, gap)
			}
		}

		canonical := CanonicalLegalHoldEvent(
			r.ID, r.HoldID, r.Action, r.NewStatus, r.ActorID,
			r.CreatedAt.UTC().Unix(),
		)
		if !Verify(prevHash, canonical, secret, r.RowHash) {
			res.Breaks = append(res.Breaks, ChainBreak{
				SeqNo: r.SeqNo, RowID: r.ID, Actual: r.RowHash,
			})
		}

		prevHash = r.RowHash
		prevSeqNo = r.SeqNo
	}
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("verify legal_hold_events: rows: %w", err)
	}
	res.OK = len(res.Gaps) == 0 && len(res.Breaks) == 0
	res.Duration = time.Since(start)
	return res, nil
}

// AuditPurgeRunRow — minimal read model for audit_purge_runs verification.
type AuditPurgeRunRow struct {
	ID          string
	CutoffEpoch int64
	RowsDeleted int
	Target      string
	CompletedAt time.Time
	SeqNo       int64
	RowHash     []byte
}

// VerifyAuditPurgeRuns верифицирует chain integrity для audit_purge_runs.
// Покрывает как coordinated (retention_hold.go), так и non-coordinated
// (retention.go RecordPurgeRun) purge paths.
func VerifyAuditPurgeRuns(ctx context.Context, db *sql.DB, secret []byte) (VerifyResult, error) {
	start := time.Now()
	res := VerifyResult{Table: "audit_purge_runs"}

	rows, err := db.QueryContext(ctx,
		`SELECT id, extract(epoch FROM cutoff)::bigint, rows_deleted,
		        coalesce(target,''), completed_at, seq_no, row_hash,
		        coalesce(canonical_version,'v1'),
		        coalesce(org_id::text,'00000000-0000-0000-0000-000000000001'),
		        coalesce(scope,'global')
		 FROM audit_purge_runs
		 WHERE seq_no IS NOT NULL AND row_hash IS NOT NULL
		 ORDER BY seq_no`)
	if err != nil {
		return res, fmt.Errorf("verify audit_purge_runs: query: %w", err)
	}
	defer rows.Close()

	var prevHash []byte
	var prevSeqNo int64

	for rows.Next() {
		var r AuditPurgeRunRow
		var canonVer, orgID, scope string
		if err := rows.Scan(
			&r.ID, &r.CutoffEpoch, &r.RowsDeleted, &r.Target,
			&r.CompletedAt, &r.SeqNo, &r.RowHash,
			&canonVer, &orgID, &scope,
		); err != nil {
			return res, fmt.Errorf("verify audit_purge_runs: scan: %w", err)
		}
		res.RowCount++

		if res.RowCount > 1 && r.SeqNo != prevSeqNo+1 {
			for gap := prevSeqNo + 1; gap < r.SeqNo; gap++ {
				res.Gaps = append(res.Gaps, gap)
			}
		}

		var canonical string
		if canonVer == "v2" {
			canonical = CanonicalAuditPurgeRunV2(
				r.ID, r.CutoffEpoch, r.RowsDeleted, r.Target,
				r.CompletedAt.UTC().Unix(), orgID, scope,
			)
		} else {
			canonical = CanonicalAuditPurgeRun(
				r.ID, r.CutoffEpoch, r.RowsDeleted, r.Target,
				r.CompletedAt.UTC().Unix(),
			)
		}
		if !Verify(prevHash, canonical, secret, r.RowHash) {
			res.Breaks = append(res.Breaks, ChainBreak{
				SeqNo: r.SeqNo, RowID: r.ID, Actual: r.RowHash,
			})
		}

		prevHash = r.RowHash
		prevSeqNo = r.SeqNo
	}
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("verify audit_purge_runs: rows: %w", err)
	}
	res.OK = len(res.Gaps) == 0 && len(res.Breaks) == 0
	res.Duration = time.Since(start)
	return res, nil
}

// SignatureVerifyResult — итог проверки Ed25519 подписей anchor'ов.
type SignatureVerifyResult struct {
	Table          string
	AnchorCount    int
	UnsignedCount  int              // anchors with NULL signature (pre-W4.1)
	SignatureFails []AnchorMismatch // bad or unverifiable signatures
	OK             bool             // true if all signed anchors verified
}

// VerifyAnchorSignatures verifies Ed25519 signatures on all anchor records
// for the given table. No chain_secret required — uses the public key only.
//
// Unsigned anchors (Signature=nil) are counted but do not cause failure —
// they are pre-W4.1 records. Only anchors with a non-nil signature that
// fail verification are reported as failures.
//
// For multi-key (post-rotation) scenarios use VerifyAnchorSignaturesWithKeyring.
func VerifyAnchorSignatures(ctx context.Context, db *sql.DB, tableName string, pubKey ed25519.PublicKey) (SignatureVerifyResult, error) {
	return VerifyAnchorSignaturesWithKeyring(ctx, db, tableName, SingleKeyKeyring(pubKey))
}

// VerifyAnchorSignaturesWithKeyring verifies Ed25519 signatures using a
// SigningKeyring that supports multiple key epochs (W7 key rotation).
//
// For each signed anchor, the keyring is consulted by a.PubKeyID:
//   - empty pubkey_id → uses keyring legacy key (backward compat with pre-W4.1 anchors)
//   - known pubkey_id → verified with its registered public key
//   - unknown pubkey_id → FAIL-CLOSED: reported as signature failure
//
// Unsigned anchors (nil Signature) are counted but do not cause failure.
// Extra keys in the keyring (not referenced by any anchor) are not errors.
func VerifyAnchorSignaturesWithKeyring(ctx context.Context, db *sql.DB, tableName string, keyring *SigningKeyring) (SignatureVerifyResult, error) {
	res := SignatureVerifyResult{Table: tableName}
	repo := NewAnchorRepository(db)

	anchors, err := repo.ListAnchors(ctx, tableName)
	if err != nil {
		return res, fmt.Errorf("verify signatures %s: list: %w", tableName, err)
	}
	res.AnchorCount = len(anchors)

	for _, a := range anchors {
		if len(a.Signature) == 0 {
			res.UnsignedCount++
			continue
		}
		pub, ok := keyring.LookupSigningKey(a.PubKeyID)
		if !ok {
			// Unknown key_id: fail-closed (cannot verify, must report as failure).
			res.SignatureFails = append(res.SignatureFails, AnchorMismatch{
				AnchorID: a.ID,
				SeqLo:    a.SeqLo,
				SeqHi:    a.SeqHi,
				Stored:   a.Signature,
			})
			continue
		}
		if !VerifyAnchorSignature(&a, pub) {
			res.SignatureFails = append(res.SignatureFails, AnchorMismatch{
				AnchorID: a.ID,
				SeqLo:    a.SeqLo,
				SeqHi:    a.SeqHi,
				Stored:   a.Signature,
			})
		}
	}
	res.OK = len(res.SignatureFails) == 0
	return res, nil
}

// AnchorVerifyResult — итог проверки anchor'ов для одной таблицы.
type AnchorVerifyResult struct {
	Table       string
	AnchorCount int
	// DBMismatches: DB anchor root ≠ Merkle computed from current DB rows.
	// Detects: row modification WITHIN DB (chain break in anchor range).
	DBMismatches []AnchorMismatch
	// SinkMismatches: DB anchor root ≠ root read from external file sink.
	// Detects: DBA tamper of audit_chain_anchors AFTER external sync.
	// Only populated if sinkPath provided.
	SinkMismatches []AnchorMismatch
	SeqGaps        []int64 // gaps between anchor ranges
	OK             bool
}

// AnchorMismatch — один несовпадающий anchor.
type AnchorMismatch struct {
	AnchorID   string
	SeqLo      int64
	SeqHi      int64
	Stored     []byte // what's in DB anchor table (or file)
	Recomputed []byte // what we computed (nil = no comparison partner)
}

// VerifyAnchors recomputes Merkle roots from stored row_hashes and
// compares to audit_chain_anchors records for the given table.
//
// W3 tier: does NOT require chain_secret.
//
// Per-anchor sink resolution (Fix #2): for each DB anchor with
// SinkName="file://" and non-empty SinkRef, the referenced file is used
// for cross-reference. fallbackSinkPath is used for anchors without a
// sink_ref (e.g. older records) or as a CLI override.
//
// Reverse check (Fix #1): after iterating DB anchors, sink records for
// this table that have no matching DB anchor → SinkMismatches. This
// detects a DBA who deleted anchor rows from audit_chain_anchors.
//
// strictSink: if true, malformed NDJSON lines in sink file return error
// instead of being silently skipped.
func VerifyAnchors(ctx context.Context, db *sql.DB, tableName, fallbackSinkPath string) (AnchorVerifyResult, error) {
	return verifyAnchors(ctx, db, tableName, fallbackSinkPath, false)
}

// VerifyAnchorsStrict is like VerifyAnchors but returns an error for
// malformed NDJSON lines in the sink file (Fix #3).
func VerifyAnchorsStrict(ctx context.Context, db *sql.DB, tableName, fallbackSinkPath string) (AnchorVerifyResult, error) {
	return verifyAnchors(ctx, db, tableName, fallbackSinkPath, true)
}

func verifyAnchors(ctx context.Context, db *sql.DB, tableName, fallbackSinkPath string, strict bool) (AnchorVerifyResult, error) {
	res := AnchorVerifyResult{Table: tableName}
	repo := NewAnchorRepository(db)

	anchors, err := repo.ListAnchors(ctx, tableName)
	if err != nil {
		return res, fmt.Errorf("verify anchors %s: list: %w", tableName, err)
	}
	res.AnchorCount = len(anchors)

	// Determine all sink files to load (Fix #2: per-anchor sink_ref).
	// Build a set of unique file paths from sink_ref + fallbackSinkPath.
	sinkFiles := make(map[string]bool)
	for _, a := range anchors {
		if a.SinkName == "file://" && a.SinkRef != "" {
			path := strings.TrimPrefix(a.SinkRef, "file://")
			if path != "" {
				sinkFiles[path] = true
			}
		}
	}
	if fallbackSinkPath != "" {
		sinkFiles[fallbackSinkPath] = true
	}

	// Load all unique sink files into combined index.
	// key = "table:seqLo:seqHi", val = merkle_root_hex
	var combinedSinkIndex map[string]string
	if len(sinkFiles) > 0 {
		combinedSinkIndex = make(map[string]string)
		for path := range sinkFiles {
			idx, err := loadSinkAnchors(path, strict)
			if err != nil {
				return res, fmt.Errorf("verify anchors %s: read sink %s: %w", tableName, path, err)
			}
			for k, v := range idx {
				combinedSinkIndex[k] = v
			}
		}
	}

	// W3.2 Fix #1 — Reverse check: sink records missing from DB.
	// A DBA could delete rows from audit_chain_anchors after the file was written.
	// Without this check, VerifyAnchors would return OK (DB empty → early return).
	if combinedSinkIndex != nil {
		dbKeys := make(map[string]bool, len(anchors))
		for _, a := range anchors {
			dbKeys[fmt.Sprintf("%s:%d:%d", tableName, a.SeqLo, a.SeqHi)] = true
		}
		for sinkKey, sinkRootHex := range combinedSinkIndex {
			// Only check keys for this table.
			if !strings.HasPrefix(sinkKey, tableName+":") {
				continue
			}
			if !dbKeys[sinkKey] {
				// Sink has a record, DB does not — anchor row was deleted.
				sinkRootBytes, _ := hexToBytes(sinkRootHex)
				res.SinkMismatches = append(res.SinkMismatches, AnchorMismatch{
					AnchorID:   "", // no DB ID — record deleted
					SeqLo:      parseSinkKeySeqLo(sinkKey),
					SeqHi:      parseSinkKeySeqHi(sinkKey),
					Recomputed: sinkRootBytes, // what sink says existed
					// Stored = nil signals "anchor deleted from DB"
				})
			}
		}
	}

	// If DB has no anchors (possibly deleted) and sink check already caught that,
	// proceed to report. Don't early-return OK just because DB is empty.
	if len(anchors) == 0 {
		res.OK = len(res.SinkMismatches) == 0 && len(res.SeqGaps) == 0
		return res, nil
	}

	// Check anchor coverage continuity.
	for i := 1; i < len(anchors); i++ {
		prev, curr := anchors[i-1], anchors[i]
		if curr.SeqLo != prev.SeqHi+1 {
			for gap := prev.SeqHi + 1; gap < curr.SeqLo; gap++ {
				res.SeqGaps = append(res.SeqGaps, gap)
			}
		}
	}

	// Forward checks: DB anchor → recomputed Merkle + sink cross-reference.
	for _, a := range anchors {
		// DB integrity: recompute Merkle from current row_hashes.
		hashes, err := repo.FetchRowHashes(ctx, tableName, a.SeqLo-1, a.SeqHi)
		if err != nil {
			return res, fmt.Errorf("verify anchors %s: fetch hashes [%d,%d]: %w",
				tableName, a.SeqLo, a.SeqHi, err)
		}
		recomputed := ComputeMerkleRoot(hashes)
		if !merkleEqual(recomputed, a.MerkleRoot) {
			res.DBMismatches = append(res.DBMismatches, AnchorMismatch{
				AnchorID:   a.ID,
				SeqLo:      a.SeqLo,
				SeqHi:      a.SeqHi,
				Stored:     a.MerkleRoot,
				Recomputed: recomputed,
			})
		}

		// External witness: compare DB anchor root to sink root.
		if combinedSinkIndex != nil {
			key := fmt.Sprintf("%s:%d:%d", tableName, a.SeqLo, a.SeqHi)
			sinkRootHex, found := combinedSinkIndex[key]
			if !found && a.SinkOK {
				// DB says sink was written successfully, but we can't find it.
				res.SinkMismatches = append(res.SinkMismatches, AnchorMismatch{
					AnchorID: a.ID,
					SeqLo:    a.SeqLo,
					SeqHi:    a.SeqHi,
					Stored:   a.MerkleRoot,
					// Recomputed = nil → "missing from sink file"
				})
			} else if found {
				sinkRootBytes, _ := hexToBytes(sinkRootHex)
				if !merkleEqual(sinkRootBytes, a.MerkleRoot) {
					res.SinkMismatches = append(res.SinkMismatches, AnchorMismatch{
						AnchorID:   a.ID,
						SeqLo:      a.SeqLo,
						SeqHi:      a.SeqHi,
						Stored:     a.MerkleRoot,  // DB anchor root
						Recomputed: sinkRootBytes, // what sink says
					})
				}
			}
		}
	}

	res.OK = len(res.DBMismatches) == 0 && len(res.SinkMismatches) == 0 && len(res.SeqGaps) == 0
	return res, nil
}

// loadSinkAnchors reads the NDJSON anchor file and builds an index.
// strict=true returns error for malformed NDJSON lines (Fix #3).
func loadSinkAnchors(sinkPath string, strict bool) (map[string]string, error) {
	data, err := os.ReadFile(sinkPath)
	if err != nil {
		return nil, fmt.Errorf("read sink file: %w", err)
	}
	index := make(map[string]string)
	for lineNum, raw := range bytes.Split(data, []byte("\n")) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		var rec struct {
			V             int    `json:"v"`
			Table         string `json:"table"`
			SeqLo         int64  `json:"seq_lo"`
			SeqHi         int64  `json:"seq_hi"`
			MerkleRootHex string `json:"merkle_root_hex"`
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			if strict {
				return nil, fmt.Errorf("malformed NDJSON line %d in %s: %w", lineNum+1, sinkPath, err)
			}
			continue
		}
		if rec.V == 1 && rec.Table != "" {
			key := fmt.Sprintf("%s:%d:%d", rec.Table, rec.SeqLo, rec.SeqHi)
			index[key] = rec.MerkleRootHex
		}
	}
	return index, nil
}

// parseSinkKeySeqLo/Hi extract seq_lo and seq_hi from "table:seqLo:seqHi".
func parseSinkKeySeqLo(key string) int64 {
	parts := strings.SplitN(key, ":", 3)
	if len(parts) < 3 {
		return 0
	}
	// parts[1] = seqLo
	var v int64
	fmt.Sscanf(parts[1], "%d", &v)
	return v
}

func parseSinkKeySeqHi(key string) int64 {
	parts := strings.SplitN(key, ":", 3)
	if len(parts) < 3 {
		return 0
	}
	var v int64
	fmt.Sscanf(parts[2], "%d", &v)
	return v
}

// hexToBytes converts hex string to bytes; returns nil on error.
func hexToBytes(h string) ([]byte, error) {
	if len(h)%2 != 0 {
		return nil, fmt.Errorf("odd hex string")
	}
	b := make([]byte, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		hi, lo := fromHexChar(h[i]), fromHexChar(h[i+1])
		if hi == 255 || lo == 255 {
			return nil, fmt.Errorf("invalid hex")
		}
		b[i/2] = hi<<4 | lo
	}
	return b, nil
}

func fromHexChar(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 255
}

func merkleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// pqArrayScan — helper для сканирования pq.StringArray в []string.
// Упрощённый вариант без pq dependency в chain package.
func pqArrayScan(dest *[]string) interface{} {
	return pqStringArrayScanner{dest}
}

type pqStringArrayScanner struct {
	dest *[]string
}

func (s pqStringArrayScanner) Scan(v interface{}) error {
	if v == nil {
		*s.dest = nil
		return nil
	}
	switch sv := v.(type) {
	case string:
		if sv == "{}" || sv == "" {
			*s.dest = nil
			return nil
		}
		// Parse {a,b,c} format.
		sv = sv[1 : len(sv)-1]
		if sv == "" {
			*s.dest = nil
			return nil
		}
		parts := splitPGArray(sv)
		*s.dest = parts
	case []byte:
		return s.Scan(string(sv))
	}
	return nil
}

func splitPGArray(s string) []string {
	var result []string
	var current []byte
	for _, ch := range s {
		if ch == ',' {
			result = append(result, string(current))
			current = current[:0]
		} else {
			current = append(current, byte(ch))
		}
	}
	if len(current) > 0 {
		result = append(result, string(current))
	}
	return result
}

// ---------------------------------------------------------------------------
// W7: Chain secret keyring — multi-epoch HMAC verification
// ---------------------------------------------------------------------------

// VerifyAuditLogsWithKeyring verifies audit_logs chain integrity using a
// ChainSecretKeyring that supports AUDIT_CHAIN_SECRET rotation (W7).
//
// For each row, the keyring is queried by seq_no to find the correct HMAC secret.
// Rows with seq_no not covered by any epoch → BREAK (fail-closed).
// Legacy usage (single secret) is covered by SingleSecretKeyring(secret).
func VerifyAuditLogsWithKeyring(ctx context.Context, db *sql.DB, keyring *ChainSecretKeyring) (VerifyResult, error) {
	start := time.Now()
	res := VerifyResult{Table: "audit_logs"}

	rows, err := db.QueryContext(ctx,
		`SELECT id, coalesce(user_id::text,''), coalesce(model,''),
		        coalesce(provider,''), coalesce(endpoint,''), status_code,
		        coalesce(prompt_tokens,0), coalesce(completion_tokens,0),
		        coalesce(total_tokens,0), coalesce(cost_usd,0),
		        coalesce(pii_detected,false), coalesce(pii_types,'{}'),
		        coalesce(policy_action,''), coalesce(outcome,''),
		        coalesce(fallback_reason,''), coalesce(usage_source,''),
		        created_at, seq_no, row_hash,
		        coalesce(canonical_version,'v1'),
		        coalesce(org_id::text,'00000000-0000-0000-0000-000000000001')
		 FROM audit_logs
		 WHERE seq_no IS NOT NULL AND row_hash IS NOT NULL
		 ORDER BY seq_no`)
	if err != nil {
		return res, fmt.Errorf("verify audit_logs (keyring): query: %w", err)
	}
	defer rows.Close()

	var prevHash []byte
	var prevSeqNo int64

	for rows.Next() {
		var r AuditRow
		var piiTypes []string
		var canonVer, orgID string
		if err := rows.Scan(
			&r.ID, &r.UserID, &r.Model, &r.Provider, &r.Endpoint,
			&r.StatusCode, &r.PromptTokens, &r.CompletionTokens, &r.TotalTokens,
			&r.CostUSD, &r.PIIDetected, pqArrayScan(&piiTypes),
			&r.PolicyAction, &r.Outcome, &r.FallbackReason, &r.UsageSource,
			&r.CreatedAt, &r.SeqNo, &r.RowHash,
			&canonVer, &orgID,
		); err != nil {
			return res, fmt.Errorf("verify audit_logs (keyring): scan: %w", err)
		}
		r.PIITypes = piiTypes
		res.RowCount++

		if res.RowCount > 1 && r.SeqNo != prevSeqNo+1 {
			for gap := prevSeqNo + 1; gap < r.SeqNo; gap++ {
				res.Gaps = append(res.Gaps, gap)
			}
		}

		secret, ok := keyring.LookupSecret(r.SeqNo)
		if !ok {
			res.Breaks = append(res.Breaks, ChainBreak{
				SeqNo: r.SeqNo, RowID: r.ID, Actual: r.RowHash,
			})
			prevHash = r.RowHash
			prevSeqNo = r.SeqNo
			continue
		}

		var canonical string
		if canonVer == "v2" {
			canonical = CanonicalAuditLogV2(
				r.ID, r.UserID, r.Model, r.Provider, r.Endpoint,
				r.StatusCode, r.PromptTokens, r.CompletionTokens, r.TotalTokens,
				CostMicrocents(r.CostUSD),
				r.PIIDetected, r.PIITypes,
				r.PolicyAction, r.Outcome, r.FallbackReason, r.UsageSource,
				r.CreatedAt.UTC().Unix(), orgID,
			)
		} else {
			canonical = CanonicalAuditLog(
				r.ID, r.UserID, r.Model, r.Provider, r.Endpoint,
				r.StatusCode, r.PromptTokens, r.CompletionTokens, r.TotalTokens,
				CostMicrocents(r.CostUSD),
				r.PIIDetected, r.PIITypes,
				r.PolicyAction, r.Outcome, r.FallbackReason, r.UsageSource,
				r.CreatedAt.UTC().Unix(),
			)
		}
		if !Verify(prevHash, canonical, secret, r.RowHash) {
			res.Breaks = append(res.Breaks, ChainBreak{
				SeqNo: r.SeqNo, RowID: r.ID, Actual: r.RowHash,
			})
		}
		prevHash = r.RowHash
		prevSeqNo = r.SeqNo
	}
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("verify audit_logs (keyring): rows: %w", err)
	}
	res.OK = len(res.Gaps) == 0 && len(res.Breaks) == 0
	res.Duration = time.Since(start)
	return res, nil
}

// VerifyAdminEventLogsWithKeyring verifies admin_event_logs chain integrity
// using the W7 multi-epoch HMAC keyring.
func VerifyAdminEventLogsWithKeyring(ctx context.Context, db *sql.DB, keyring *ChainSecretKeyring) (VerifyResult, error) {
	start := time.Now()
	res := VerifyResult{Table: "admin_event_logs"}
	if keyring == nil {
		return res, fmt.Errorf("verify admin_event_logs (keyring): nil keyring")
	}

	rows, err := db.QueryContext(ctx,
		`SELECT id, coalesce(actor_user_id::text,''), action, resource,
		        coalesce(target_id,''), path, method, status_code, success,
		        created_at, seq_no, row_hash,
		        coalesce(canonical_version,'v1'),
		        coalesce(org_id::text,'00000000-0000-0000-0000-000000000001'),
		        coalesce(source_org_id::text,''),
		        coalesce(target_org_id::text,'')
		 FROM admin_event_logs
		 WHERE seq_no IS NOT NULL AND row_hash IS NOT NULL
		 ORDER BY seq_no`)
	if err != nil {
		return res, fmt.Errorf("verify admin_event_logs (keyring): query: %w", err)
	}
	defer rows.Close()

	var prevHash []byte
	var prevSeqNo int64
	for rows.Next() {
		var r AdminEventRow
		var canonVer, orgID, sourceOrgID, targetOrgID string
		if err := rows.Scan(
			&r.ID, &r.ActorUserID, &r.Action, &r.Resource,
			&r.TargetID, &r.Path, &r.Method, &r.StatusCode, &r.Success,
			&r.CreatedAt, &r.SeqNo, &r.RowHash,
			&canonVer, &orgID, &sourceOrgID, &targetOrgID,
		); err != nil {
			return res, fmt.Errorf("verify admin_event_logs (keyring): scan: %w", err)
		}
		res.RowCount++

		if res.RowCount > 1 && r.SeqNo != prevSeqNo+1 {
			for gap := prevSeqNo + 1; gap < r.SeqNo; gap++ {
				res.Gaps = append(res.Gaps, gap)
			}
		}

		secret, ok := keyring.LookupSecret(r.SeqNo)
		if !ok {
			res.Breaks = append(res.Breaks, ChainBreak{SeqNo: r.SeqNo, RowID: r.ID, Actual: r.RowHash})
			prevHash = r.RowHash
			prevSeqNo = r.SeqNo
			continue
		}

		var canonical string
		if canonVer == "v2" {
			canonical = CanonicalAdminEventLogV2(
				r.ID, r.ActorUserID, r.Action, r.Resource, r.TargetID,
				r.Path, r.Method, r.StatusCode, r.Success,
				r.CreatedAt.UTC().Unix(),
				orgID, sourceOrgID, targetOrgID,
			)
		} else {
			canonical = CanonicalAdminEventLog(
				r.ID, r.ActorUserID, r.Action, r.Resource, r.TargetID,
				r.Path, r.Method, r.StatusCode, r.Success,
				r.CreatedAt.UTC().Unix(),
			)
		}
		if !Verify(prevHash, canonical, secret, r.RowHash) {
			res.Breaks = append(res.Breaks, ChainBreak{SeqNo: r.SeqNo, RowID: r.ID, Actual: r.RowHash})
		}

		prevHash = r.RowHash
		prevSeqNo = r.SeqNo
	}
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("verify admin_event_logs (keyring): rows: %w", err)
	}
	res.OK = len(res.Gaps) == 0 && len(res.Breaks) == 0
	res.Duration = time.Since(start)
	return res, nil
}

// VerifyLegalHoldEventsWithKeyring verifies legal_hold_events chain integrity
// using the W7 multi-epoch HMAC keyring.
func VerifyLegalHoldEventsWithKeyring(ctx context.Context, db *sql.DB, keyring *ChainSecretKeyring) (VerifyResult, error) {
	start := time.Now()
	res := VerifyResult{Table: "legal_hold_events"}
	if keyring == nil {
		return res, fmt.Errorf("verify legal_hold_events (keyring): nil keyring")
	}

	rows, err := db.QueryContext(ctx,
		`SELECT id, hold_id::text, action, new_status,
		        coalesce(actor_id::text,''), created_at, seq_no, row_hash
		 FROM legal_hold_events
		 WHERE seq_no IS NOT NULL AND row_hash IS NOT NULL
		 ORDER BY seq_no`)
	if err != nil {
		return res, fmt.Errorf("verify legal_hold_events (keyring): query: %w", err)
	}
	defer rows.Close()

	var prevHash []byte
	var prevSeqNo int64
	for rows.Next() {
		var r LegalHoldEventRow
		if err := rows.Scan(
			&r.ID, &r.HoldID, &r.Action, &r.NewStatus,
			&r.ActorID, &r.CreatedAt, &r.SeqNo, &r.RowHash,
		); err != nil {
			return res, fmt.Errorf("verify legal_hold_events (keyring): scan: %w", err)
		}
		res.RowCount++

		if res.RowCount > 1 && r.SeqNo != prevSeqNo+1 {
			for gap := prevSeqNo + 1; gap < r.SeqNo; gap++ {
				res.Gaps = append(res.Gaps, gap)
			}
		}

		secret, ok := keyring.LookupSecret(r.SeqNo)
		if !ok {
			res.Breaks = append(res.Breaks, ChainBreak{SeqNo: r.SeqNo, RowID: r.ID, Actual: r.RowHash})
			prevHash = r.RowHash
			prevSeqNo = r.SeqNo
			continue
		}

		canonical := CanonicalLegalHoldEvent(
			r.ID, r.HoldID, r.Action, r.NewStatus, r.ActorID,
			r.CreatedAt.UTC().Unix(),
		)
		if !Verify(prevHash, canonical, secret, r.RowHash) {
			res.Breaks = append(res.Breaks, ChainBreak{SeqNo: r.SeqNo, RowID: r.ID, Actual: r.RowHash})
		}

		prevHash = r.RowHash
		prevSeqNo = r.SeqNo
	}
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("verify legal_hold_events (keyring): rows: %w", err)
	}
	res.OK = len(res.Gaps) == 0 && len(res.Breaks) == 0
	res.Duration = time.Since(start)
	return res, nil
}

// VerifyAuditPurgeRunsWithKeyring verifies audit_purge_runs chain integrity
// using the W7 multi-epoch HMAC keyring.
func VerifyAuditPurgeRunsWithKeyring(ctx context.Context, db *sql.DB, keyring *ChainSecretKeyring) (VerifyResult, error) {
	start := time.Now()
	res := VerifyResult{Table: "audit_purge_runs"}
	if keyring == nil {
		return res, fmt.Errorf("verify audit_purge_runs (keyring): nil keyring")
	}

	rows, err := db.QueryContext(ctx,
		`SELECT id, extract(epoch FROM cutoff)::bigint, rows_deleted,
		        coalesce(target,''), completed_at, seq_no, row_hash,
		        coalesce(canonical_version,'v1'),
		        coalesce(org_id::text,'00000000-0000-0000-0000-000000000001'),
		        coalesce(scope,'global')
		 FROM audit_purge_runs
		 WHERE seq_no IS NOT NULL AND row_hash IS NOT NULL
		 ORDER BY seq_no`)
	if err != nil {
		return res, fmt.Errorf("verify audit_purge_runs (keyring): query: %w", err)
	}
	defer rows.Close()

	var prevHash []byte
	var prevSeqNo int64
	for rows.Next() {
		var r AuditPurgeRunRow
		var canonVer, orgID, scope string
		if err := rows.Scan(
			&r.ID, &r.CutoffEpoch, &r.RowsDeleted, &r.Target,
			&r.CompletedAt, &r.SeqNo, &r.RowHash,
			&canonVer, &orgID, &scope,
		); err != nil {
			return res, fmt.Errorf("verify audit_purge_runs (keyring): scan: %w", err)
		}
		res.RowCount++

		if res.RowCount > 1 && r.SeqNo != prevSeqNo+1 {
			for gap := prevSeqNo + 1; gap < r.SeqNo; gap++ {
				res.Gaps = append(res.Gaps, gap)
			}
		}

		secret, ok := keyring.LookupSecret(r.SeqNo)
		if !ok {
			res.Breaks = append(res.Breaks, ChainBreak{SeqNo: r.SeqNo, RowID: r.ID, Actual: r.RowHash})
			prevHash = r.RowHash
			prevSeqNo = r.SeqNo
			continue
		}

		var canonical string
		if canonVer == "v2" {
			canonical = CanonicalAuditPurgeRunV2(
				r.ID, r.CutoffEpoch, r.RowsDeleted, r.Target,
				r.CompletedAt.UTC().Unix(), orgID, scope,
			)
		} else {
			canonical = CanonicalAuditPurgeRun(
				r.ID, r.CutoffEpoch, r.RowsDeleted, r.Target,
				r.CompletedAt.UTC().Unix(),
			)
		}
		if !Verify(prevHash, canonical, secret, r.RowHash) {
			res.Breaks = append(res.Breaks, ChainBreak{SeqNo: r.SeqNo, RowID: r.ID, Actual: r.RowHash})
		}

		prevHash = r.RowHash
		prevSeqNo = r.SeqNo
	}
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("verify audit_purge_runs (keyring): rows: %w", err)
	}
	res.OK = len(res.Gaps) == 0 && len(res.Breaks) == 0
	res.Duration = time.Since(start)
	return res, nil
}

package chain

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// VerifyResult — итог верификации одной таблицы.
type VerifyResult struct {
	Table      string
	RowCount   int // total chained rows scanned
	Gaps       []int64      // seq_no значения которые пропущены
	Breaks     []ChainBreak // rows где hash не совпадает
	OK         bool         // true если Gaps и Breaks пусты
	Duration   time.Duration
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
		        created_at, seq_no, row_hash
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
		if err := rows.Scan(
			&r.ID, &r.UserID, &r.Model, &r.Provider, &r.Endpoint,
			&r.StatusCode, &r.PromptTokens, &r.CompletionTokens, &r.TotalTokens,
			&r.CostUSD, &r.PIIDetected, pqArrayScan(&piiTypes),
			&r.PolicyAction, &r.Outcome, &r.FallbackReason, &r.UsageSource,
			&r.CreatedAt, &r.SeqNo, &r.RowHash,
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

		// Chain break detection.
		canonical := CanonicalAuditLog(
			r.ID, r.UserID, r.Model, r.Provider, r.Endpoint,
			r.StatusCode, r.PromptTokens, r.CompletionTokens, r.TotalTokens,
			CostMicrocents(r.CostUSD),
			r.PIIDetected, r.PIITypes,
			r.PolicyAction, r.Outcome, r.FallbackReason, r.UsageSource,
			r.CreatedAt.UTC().Unix(),
		)
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
		        created_at, seq_no, row_hash
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
		if err := rows.Scan(
			&r.ID, &r.ActorUserID, &r.Action, &r.Resource,
			&r.TargetID, &r.Path, &r.Method, &r.StatusCode, &r.Success,
			&r.CreatedAt, &r.SeqNo, &r.RowHash,
		); err != nil {
			return res, fmt.Errorf("verify admin_event_logs: scan: %w", err)
		}
		res.RowCount++

		if res.RowCount > 1 && r.SeqNo != prevSeqNo+1 {
			for gap := prevSeqNo + 1; gap < r.SeqNo; gap++ {
				res.Gaps = append(res.Gaps, gap)
			}
		}

		canonical := CanonicalAdminEventLog(
			r.ID, r.ActorUserID, r.Action, r.Resource, r.TargetID,
			r.Path, r.Method, r.StatusCode, r.Success,
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
		        coalesce(target,''), completed_at, seq_no, row_hash
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
		if err := rows.Scan(
			&r.ID, &r.CutoffEpoch, &r.RowsDeleted, &r.Target,
			&r.CompletedAt, &r.SeqNo, &r.RowHash,
		); err != nil {
			return res, fmt.Errorf("verify audit_purge_runs: scan: %w", err)
		}
		res.RowCount++

		if res.RowCount > 1 && r.SeqNo != prevSeqNo+1 {
			for gap := prevSeqNo + 1; gap < r.SeqNo; gap++ {
				res.Gaps = append(res.Gaps, gap)
			}
		}

		canonical := CanonicalAuditPurgeRun(
			r.ID, r.CutoffEpoch, r.RowsDeleted, r.Target,
			r.CompletedAt.UTC().Unix(),
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
		return res, fmt.Errorf("verify audit_purge_runs: rows: %w", err)
	}
	res.OK = len(res.Gaps) == 0 && len(res.Breaks) == 0
	res.Duration = time.Since(start)
	return res, nil
}

// AnchorVerifyResult — итог проверки anchor'ов для одной таблицы.
type AnchorVerifyResult struct {
	Table         string
	AnchorCount   int
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
// W3 tier: does NOT require chain_secret. Only needs DB access to
// read row_hash values (and optionally the file sink path).
//
// sinkPath: if non-empty, also reads the NDJSON anchor file and
// cross-references each DB anchor record against the external sink.
// This is the external-witness verification — defends against a DBA
// who rewrites both DB rows AND DB anchor table: the file records
// written at anchor time are independent and not in the DB.
func VerifyAnchors(ctx context.Context, db *sql.DB, tableName, sinkPath string) (AnchorVerifyResult, error) {
	res := AnchorVerifyResult{Table: tableName}
	repo := NewAnchorRepository(db)

	anchors, err := repo.ListAnchors(ctx, tableName)
	if err != nil {
		return res, fmt.Errorf("verify anchors %s: list: %w", tableName, err)
	}
	if len(anchors) == 0 {
		res.OK = true
		return res, nil
	}
	res.AnchorCount = len(anchors)

	// Optional: load external sink records for cross-reference.
	var sinkIndex map[string]string // key = "table:seqLo:seqHi", val = merkle_root_hex
	if sinkPath != "" {
		sinkIndex, err = loadSinkAnchors(sinkPath)
		if err != nil {
			return res, fmt.Errorf("verify anchors %s: read sink %s: %w", tableName, sinkPath, err)
		}
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

	for _, a := range anchors {
		// 1. DB integrity check: recompute Merkle from current DB row_hashes.
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

		// 2. External witness check: compare DB anchor root to sink file root.
		if sinkIndex != nil {
			key := fmt.Sprintf("%s:%d:%d", tableName, a.SeqLo, a.SeqHi)
			sinkRootHex, found := sinkIndex[key]
			if !found {
				// Anchor exists in DB but not in sink — possible if sink write failed
				// (sink_ok=false) or sink file was modified/truncated.
				if a.SinkOK {
					// sink_ok=true but no matching record → sink tampered or lost.
					res.SinkMismatches = append(res.SinkMismatches, AnchorMismatch{
						AnchorID: a.ID,
						SeqLo:    a.SeqLo,
						SeqHi:    a.SeqHi,
						Stored:   a.MerkleRoot,
						// Recomputed = nil signals "not found in sink"
					})
				}
			} else {
				sinkRootBytes, _ := hexToBytes(sinkRootHex)
				if !merkleEqual(sinkRootBytes, a.MerkleRoot) {
					res.SinkMismatches = append(res.SinkMismatches, AnchorMismatch{
						AnchorID:   a.ID,
						SeqLo:      a.SeqLo,
						SeqHi:      a.SeqHi,
						Stored:     a.MerkleRoot,    // DB anchor root
						Recomputed: sinkRootBytes,   // what sink says
					})
				}
			}
		}
	}

	res.OK = len(res.DBMismatches) == 0 && len(res.SinkMismatches) == 0 && len(res.SeqGaps) == 0
	return res, nil
}

// loadSinkAnchors reads the NDJSON anchor file and builds an index
// keyed by "table:seqLo:seqHi" → merkle_root_hex.
func loadSinkAnchors(sinkPath string) (map[string]string, error) {
	data, err := os.ReadFile(sinkPath)
	if err != nil {
		return nil, fmt.Errorf("read sink file: %w", err)
	}
	index := make(map[string]string)
	for _, raw := range bytes.Split(data, []byte("\n")) {
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
			continue // malformed line — skip, don't abort
		}
		if rec.V == 1 && rec.Table != "" {
			key := fmt.Sprintf("%s:%d:%d", rec.Table, rec.SeqLo, rec.SeqHi)
			index[key] = rec.MerkleRootHex
		}
	}
	return index, nil
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

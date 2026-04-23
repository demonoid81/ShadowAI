package chain

import (
	"context"
	"database/sql"
	"fmt"
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

//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
//
// PR-L2.1 / PR-L2.2: СУЖАЕТ race-window между apply_hold и purge,
// но НЕ устраняет его полностью.
//
// Было (PR-L2): race от snapshot-read (ActiveUserIDs в Go) до
// DELETE-statement'а — десятки миллисекунд с сетевым round-trip'ом.
//
// Стало (PR-L2.1): race только внутри одного DELETE statement'а.
// PostgreSQL default READ COMMITTED даёт statement-level snapshot,
// установленный в начале DELETE. Hold, applied ПОСЛЕ начала
// statement'а, НЕ виден этому statement'у → его rows всё ещё
// могут удалиться в том же tick'е (на следующем tick'е — уже
// защищены).
//
// Residual race-window зависит от chunkSize (длина одного DELETE).
// Для prod chunkSize=1000 это миллисекунды; acceptable для
// большинства compliance-рамок. ДЛЯ СТРОГОГО COMPLIANCE (true
// race-free):
//   - SERIALIZABLE isolation на purge transaction +
//     apply_hold retry logic; или
//   - advisory lock: apply_hold → pg_advisory_lock(hold_ns),
//     purge → pg_advisory_lock(hold_ns). Performance-impact на
//     apply_hold (acceptable, apply редкий).
//
// Эти design'ы — roadmap (PR-L3 coordination). Пока — документируем
// ограничение и полагаемся на `AUDIT_PURGE_INTERVAL` >= некоторой
// retention margin'ы (hold применён ДО cutoff, не после).

package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/legalholdcoord"
	"github.com/shadowai/backend/internal/legalholdselector"
)

type queryScopeHoldProtection struct {
	HoldID          string
	OrgID           string
	TargetUserID    string
	SelectorJSON    string
	SelectorHash    string
	SelectorVersion int
}

type queryScopeCompileFailure struct {
	HoldID          string
	OrgID           string
	TargetUserID    string
	SelectorHash    string
	SelectorVersion int
	Err             error
}

func (e *queryScopeCompileFailure) Error() string {
	return fmt.Sprintf("legal hold query_scope compile failed for hold %s: %v", e.HoldID, e.Err)
}

func (e *queryScopeCompileFailure) Unwrap() error {
	return e.Err
}

type queryContexter interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// PurgeOlderThanRespectingHoldsAndRecordRun — PR-L3 coordinated
// purge. Выполняет всё в одной tx под `legalholdcoord.
// AcquireHoldPurgeLock`, включая INSERT в audit_purge_runs.
// Commit-order guarantee с apply_hold (см. legalholdcoord package
// comment):
//
//   - apply_hold commit → purge commit: purge видит hold, rows
//     защищены.
//   - purge commit → apply_hold commit: rows могут удалиться
//     (hold ещё не существовал на момент purge-commit'а).
//
// Chunked DELETE выполняется в рамках одной tx: lock держится
// всё время purge. Это acceptable для редкого scheduler'а
// (AUDIT_PURGE_INTERVAL обычно >= минуты). Apply_hold может
// подождать один purge-tick — редкое событие.
//
// target — параметр для audit_purge_runs (PurgeTargetAuditLogs).
//
// Error на любом шаге (tx/lock/delete/record) → rollback,
// возврат err. Caller (scheduler) пишет admin_event на failure.
func (r *Repository) PurgeOlderThanRespectingHoldsAndRecordRun(ctx context.Context, cutoff time.Time, chunkSize int) (int, error) {
	if chunkSize <= 0 {
		return 0, fmt.Errorf("purge: chunkSize must be > 0, got %d", chunkSize)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("purge: begin tx: %w", err)
	}
	// Defensive rollback; commit ниже — duplicate rollback no-op.
	defer func() { _ = tx.Rollback() }()

	if err := legalholdcoord.AcquireHoldPurgeLock(ctx, tx); err != nil {
		return 0, err
	}

	queryScopes, err := r.loadQueryScopeHoldProtections(ctx, tx)
	if err != nil {
		return 0, err
	}
	delQ, delArgs, err := buildHoldAwarePurgeDelete(cutoff, chunkSize, queryScopes)
	if err != nil {
		_ = tx.Rollback()
		if recErr := r.recordQueryScopeCompileFailure(ctx, err); recErr != nil {
			return 0, fmt.Errorf("%w; record compile failure: %v", err, recErr)
		}
		return 0, err
	}

	// PR-L6: whole_user защищает все строки target user. date_range
	// защищает только строки, где created_at попадает в диапазон hold.
	// release_pending остаётся юридически действующим до ApproveRelease.
	total := 0
	for {
		res, err := tx.ExecContext(ctx, delQ, delArgs...)
		if err != nil {
			return total, fmt.Errorf("purge exec: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("purge RowsAffected: %w", err)
		}
		total += int(n)
		if n < int64(chunkSize) {
			break
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
	}

	// PR-W2.1 fix: ONE chained row per purge with actual rows_deleted.
	// Ранее была отдельная pre-purge строка с rows_deleted=0, что
	// создавало два rows в audit_purge_runs на одну операцию и ломало
	// LastPurgeRun() при одинаковом started_at в одной tx.
	// Теперь chain write встраивается в ЭТОТ INSERT (после DELETE,
	// внутри той же tx), содержит реальный rows_deleted.
	// Scheduler is always system-level global purge (scope='global', no org filter).
	if err := r.recordPurgeRunChained(ctx, tx, cutoff, total, PurgeTargetAuditLogs, "", "global"); err != nil {
		return total, fmt.Errorf("purge record run: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return total, fmt.Errorf("purge commit: %w", err)
	}
	return total, nil
}

// PurgeOlderThanRespectingHolds — retention-aware purge audit_logs,
// напрямую консультирующий legal_holds в DELETE statement'е. Этот
// метод доступен ТОЛЬКО в enterprise build (где legal_holds
// существует).
//
// Возвращает total deleted. chunkSize<=0 → error.
//
// SQL:
//
//	DELETE FROM audit_logs WHERE id IN (
//	    SELECT id FROM audit_logs
//	    WHERE created_at < $1
//	      AND (user_id IS NULL
//	           OR NOT EXISTS (
//	             SELECT 1 FROM legal_holds lh
//	             WHERE lh.status = 'active'
//	               AND lh.target_user_id = audit_logs.user_id
//	           ))
//	    LIMIT $2
//	)
//
// user_id IS NULL rows остаются eligible — это post-DSAR scrubbed
// rows, legal-hold к ним не может применяться (user'а нет).
//
// PR-L6: whole_user hold защищает все строки target user. date_range
// hold защищает только строки внутри диапазона. Pending hold'ы НЕ
// участвуют в purge-protection — нужен второй admin. release_pending
// остаётся юридически действующим до ApproveRelease.
//
// Race-window: под READ COMMITTED hold, applied после начала DELETE
// statement'а, не виден ему — его rows могут удалиться. См. package
// comment выше для полной картины и roadmap-path'ов к true race-free.
func (r *Repository) PurgeOlderThanRespectingHolds(ctx context.Context, cutoff time.Time, chunkSize int) (int, error) {
	if chunkSize <= 0 {
		return 0, fmt.Errorf("purge: chunkSize must be > 0, got %d", chunkSize)
	}
	queryScopes, err := r.loadQueryScopeHoldProtections(ctx, r.db)
	if err != nil {
		return 0, err
	}
	delQ, delArgs, err := buildHoldAwarePurgeDelete(cutoff, chunkSize, queryScopes)
	if err != nil {
		if recErr := r.recordQueryScopeCompileFailure(ctx, err); recErr != nil {
			return 0, fmt.Errorf("%w; record compile failure: %v", err, recErr)
		}
		return 0, err
	}
	total := 0
	for {
		res, err := r.db.ExecContext(ctx, delQ, delArgs...)
		if err != nil {
			return total, fmt.Errorf("purge exec: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("purge RowsAffected: %w", err)
		}
		total += int(n)
		if n < int64(chunkSize) {
			break
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
	}
	return total, nil
}

func (r *Repository) loadQueryScopeHoldProtections(ctx context.Context, q queryContexter) ([]queryScopeHoldProtection, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT id::text,
		        COALESCE(org_id::text, ''),
		        target_user_id::text,
		        COALESCE(scope_query_json::text, ''),
		        COALESCE(scope_query_hash, ''),
		        COALESCE(scope_query_version, 0)
		   FROM legal_holds
		  WHERE status IN ('active', 'release_pending')
		    AND scope_type = 'query_scope'
		  ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("purge load query_scope holds: %w", err)
	}
	defer rows.Close()

	var out []queryScopeHoldProtection
	for rows.Next() {
		var h queryScopeHoldProtection
		if err := rows.Scan(&h.HoldID, &h.OrgID, &h.TargetUserID, &h.SelectorJSON, &h.SelectorHash, &h.SelectorVersion); err != nil {
			return nil, fmt.Errorf("purge scan query_scope hold: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func buildHoldAwarePurgeDelete(cutoff time.Time, chunkSize int, queryScopes []queryScopeHoldProtection) (string, []any, error) {
	args := []any{cutoff, chunkSize}
	var queryScopeClauses []string
	for _, hold := range queryScopes {
		if hold.SelectorVersion != 1 {
			return "", nil, &queryScopeCompileFailure{
				HoldID: hold.HoldID, OrgID: hold.OrgID, TargetUserID: hold.TargetUserID,
				SelectorHash: hold.SelectorHash, SelectorVersion: hold.SelectorVersion,
				Err: fmt.Errorf("unsupported selector version %d: %w", hold.SelectorVersion, legalholdselector.ErrInvalidSelector),
			}
		}
		if strings.TrimSpace(hold.SelectorJSON) == "" {
			return "", nil, &queryScopeCompileFailure{
				HoldID: hold.HoldID, OrgID: hold.OrgID, TargetUserID: hold.TargetUserID,
				SelectorHash: hold.SelectorHash, SelectorVersion: hold.SelectorVersion,
				Err: fmt.Errorf("empty selector JSON: %w", legalholdselector.ErrInvalidSelector),
			}
		}

		userArg := len(args) + 1
		args = append(args, hold.TargetUserID)
		compiled, err := legalholdselector.Compile(json.RawMessage(hold.SelectorJSON), legalholdselector.CompileOptions{
			ArgOffset: len(args) + 1,
		})
		if err != nil {
			return "", nil, &queryScopeCompileFailure{
				HoldID: hold.HoldID, OrgID: hold.OrgID, TargetUserID: hold.TargetUserID,
				SelectorHash: hold.SelectorHash, SelectorVersion: hold.SelectorVersion,
				Err: err,
			}
		}
		queryScopeClauses = append(queryScopeClauses,
			fmt.Sprintf("(user_id = $%d AND (%s))", userArg, compiled.SQL),
		)
		args = append(args, compiled.Args...)
	}

	queryScopeProtection := ""
	if len(queryScopeClauses) > 0 {
		queryScopeProtection = "\n	      AND (user_id IS NULL OR NOT (" + strings.Join(queryScopeClauses, " OR ") + "))"
	}

	q := `DELETE FROM audit_logs WHERE id IN (
	    SELECT id FROM audit_logs
	    WHERE created_at < $1
	      AND (user_id IS NULL
	           OR NOT EXISTS (
	             SELECT 1 FROM legal_holds lh
	             WHERE lh.status IN ('active', 'release_pending')
	               AND lh.target_user_id = audit_logs.user_id
	               AND (
	                 lh.scope_type = 'whole_user'
	                 OR (
	                   lh.scope_type = 'date_range'
	                   AND lh.scope_date_from IS NOT NULL
	                   AND lh.scope_date_to IS NOT NULL
	                   AND audit_logs.created_at >= lh.scope_date_from
	                   AND audit_logs.created_at <= lh.scope_date_to
	                 )
	               )
	           ))` + queryScopeProtection + `
	    LIMIT $2
	)`
	return q, args, nil
}

func (r *Repository) recordQueryScopeCompileFailure(ctx context.Context, err error) error {
	var failure *queryScopeCompileFailure
	if !asQueryScopeCompileFailure(err, &failure) {
		return nil
	}
	meta, marshalErr := json.Marshal(map[string]any{
		"error_code":       "invalid_query_scope_selector",
		"hold_id":          failure.HoldID,
		"selector_hash":    failure.SelectorHash,
		"selector_version": failure.SelectorVersion,
		"target_user_id":   failure.TargetUserID,
		"error":            failure.Err.Error(),
	})
	if marshalErr != nil {
		return marshalErr
	}
	adminRepo := adminaudit.NewRepository(r.db)
	if len(r.chainSecret) > 0 {
		adminRepo = adminRepo.WithChainSecret(string(r.chainSecret))
	}
	return adminRepo.Insert(ctx, &domain.AdminEvent{
		Action:       "legal_hold_query_scope_compile_failed",
		Resource:     "legal_hold",
		TargetID:     failure.HoldID,
		Path:         "purge",
		Method:       "INTERNAL",
		StatusCode:   500,
		Success:      false,
		MetadataJSON: string(meta),
		OrgID:        failure.OrgID,
		TargetOrgID:  failure.OrgID,
	})
}

func asQueryScopeCompileFailure(err error, target **queryScopeCompileFailure) bool {
	return errors.As(err, target)
}

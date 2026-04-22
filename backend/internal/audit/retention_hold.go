//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
//
// PR-L2.1: устраняет race между ActiveUserIDs snapshot и DELETE
// (PR-L2). Вместо двухшагового snapshot→delete используется single
// SQL-statement с `NOT EXISTS (SELECT ... FROM legal_holds ...)`.
// PG MVCC даёт snapshot-isolated view на то же состояние
// legal_holds, что видно в момент DELETE row-scan'а — hold,
// созданный после начала statement'а, защищает rows automatically
// (если READ COMMITTED) или вся delete пропустит любые rows,
// защищённые active hold'ом на момент старта statement'а.

package audit

import (
	"context"
	"fmt"
	"time"
)

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
//	             WHERE lh.is_active = true
//	               AND lh.target_user_id = audit_logs.user_id
//	           ))
//	    LIMIT $2
//	)
//
// user_id IS NULL rows остаются eligible — это post-DSAR scrubbed
// rows, legal-hold к ним не может применяться (user'а нет).
func (r *Repository) PurgeOlderThanRespectingHolds(ctx context.Context, cutoff time.Time, chunkSize int) (int, error) {
	if chunkSize <= 0 {
		return 0, fmt.Errorf("purge: chunkSize must be > 0, got %d", chunkSize)
	}
	total := 0
	const q = `DELETE FROM audit_logs WHERE id IN (
	    SELECT id FROM audit_logs
	    WHERE created_at < $1
	      AND (user_id IS NULL
	           OR NOT EXISTS (
	             SELECT 1 FROM legal_holds lh
	             WHERE lh.is_active = true
	               AND lh.target_user_id = audit_logs.user_id
	           ))
	    LIMIT $2
	)`
	for {
		res, err := r.db.ExecContext(ctx, q, cutoff, chunkSize)
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

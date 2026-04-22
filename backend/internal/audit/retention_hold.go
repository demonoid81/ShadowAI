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
//
// Race-window: под READ COMMITTED hold, applied после начала DELETE
// statement'а, не виден ему — его rows могут удалиться. См. package
// comment выше для полной картины и roadmap-path'ов к true race-free.
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

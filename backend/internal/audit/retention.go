package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/shadowai/backend/internal/domain"
)

// PurgeTargetAuditLogs — значение поля target в audit_purge_runs для
// стандартного purge audit_logs. PR-D.1 добавил возможность трекать
// также admin_event_logs-purge через другой target-constant.
const PurgeTargetAuditLogs = "audit_logs"

// PurgeOlderThan удаляет audit_logs-rows с created_at < cutoff в
// чанках размера chunkSize. Chunking защищает от долгих lock'ов на
// большой таблице (PG не поддерживает LIMIT в DELETE напрямую, так
// что используем DELETE ... WHERE id IN (SELECT id ... LIMIT N)).
//
// Возвращает total deleted. Если chunkSize <= 0 — error.
func (r *Repository) PurgeOlderThan(ctx context.Context, cutoff time.Time, chunkSize int) (int, error) {
	if chunkSize <= 0 {
		return 0, fmt.Errorf("purge: chunkSize must be > 0, got %d", chunkSize)
	}
	total := 0
	for {
		res, err := r.db.ExecContext(ctx,
			`DELETE FROM audit_logs WHERE id IN (
				SELECT id FROM audit_logs WHERE created_at < $1 LIMIT $2
			)`, cutoff, chunkSize)
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

// RecordPurgeRun сохраняет запись о завершённом purge-run для указанной
// target-таблицы ("audit_logs" | "admin_event_logs"). Вызывающий может
// передать "" — интерпретируется как audit_logs (backward compat для
// call-site'ов до PR-D.1).
func (r *Repository) RecordPurgeRun(ctx context.Context, cutoff time.Time, rowsDeleted int, target string) error {
	if target == "" {
		target = PurgeTargetAuditLogs
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO audit_purge_runs (cutoff, rows_deleted, completed_at, target)
		 VALUES ($1, $2, now(), $3)`,
		cutoff, rowsDeleted, target)
	if err != nil {
		return fmt.Errorf("record purge run: %w", err)
	}
	return nil
}

// LastPurgeRun возвращает последний завершённый purge для target'а.
// target="" → audit_logs (default). Nil result → ещё ни разу не purge'или
// эту target-таблицу.
func (r *Repository) LastPurgeRun(ctx context.Context, target string) (*domain.PurgeRun, error) {
	if target == "" {
		target = PurgeTargetAuditLogs
	}
	var pr domain.PurgeRun
	var completed sql.NullTime
	err := r.db.QueryRowContext(ctx,
		`SELECT id, started_at, completed_at, cutoff, rows_deleted, target
		 FROM audit_purge_runs
		 WHERE completed_at IS NOT NULL AND target = $1
		 ORDER BY started_at DESC LIMIT 1`, target).
		Scan(&pr.ID, &pr.StartedAt, &completed, &pr.Cutoff, &pr.RowsDeleted, &pr.Target)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("last purge run: %w", err)
	}
	if completed.Valid {
		pr.CompletedAt = &completed.Time
	}
	return &pr, nil
}

// TotalRowsPurged — сумма rows_deleted по всем завершённым запускам
// для конкретного target'а. target="" → audit_logs.
func (r *Repository) TotalRowsPurged(ctx context.Context, target string) (int, error) {
	if target == "" {
		target = PurgeTargetAuditLogs
	}
	var total int
	err := r.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(rows_deleted), 0) FROM audit_purge_runs WHERE target = $1`,
		target).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("total rows purged: %w", err)
	}
	return total, nil
}

package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/shadowai/backend/internal/domain"
)

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
			// Последний chunk — все старые удалены.
			break
		}
		// Уважаем отменяемый context между чанками.
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
	}
	return total, nil
}

// RecordPurgeRun сохраняет запись о завершённом purge-run. started_at
// и completed_at выставляются серверным NOW() — для единого таймстемпа
// на всех узлах. Запись всегда finalized (completed_at NOT NULL).
func (r *Repository) RecordPurgeRun(ctx context.Context, cutoff time.Time, rowsDeleted int) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO audit_purge_runs (cutoff, rows_deleted, completed_at)
		 VALUES ($1, $2, now())`,
		cutoff, rowsDeleted)
	if err != nil {
		return fmt.Errorf("record purge run: %w", err)
	}
	return nil
}

// LastPurgeRun возвращает последний завершённый purge, либо nil,
// если ни одного ещё не было. Ошибка sql.ErrNoRows не пропагирует
// наружу — это не-ошибочный case для status endpoint'а.
func (r *Repository) LastPurgeRun(ctx context.Context) (*domain.PurgeRun, error) {
	var pr domain.PurgeRun
	var completed sql.NullTime
	err := r.db.QueryRowContext(ctx,
		`SELECT id, started_at, completed_at, cutoff, rows_deleted
		 FROM audit_purge_runs
		 WHERE completed_at IS NOT NULL
		 ORDER BY started_at DESC LIMIT 1`).
		Scan(&pr.ID, &pr.StartedAt, &completed, &pr.Cutoff, &pr.RowsDeleted)
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

// TotalRowsPurged — сумма rows_deleted по всем завершённым запускам.
// Используется status endpoint'ом для ops-visibility.
func (r *Repository) TotalRowsPurged(ctx context.Context) (int, error) {
	var total int
	err := r.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(rows_deleted), 0) FROM audit_purge_runs`).
		Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("total rows purged: %w", err)
	}
	return total, nil
}

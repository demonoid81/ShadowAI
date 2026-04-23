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
	return r.PurgeOlderThanExcept(ctx, cutoff, chunkSize, nil)
}

// PurgeOlderThanExcept — PR-L2: retention-aware purge. Удаляет
// audit_logs-rows с created_at < cutoff, НО исключает rows, где
// user_id присутствует в exceptUserIDs (список user'ов под active
// legal hold). user_id IS NULL rows всегда eligible для purge
// (после DSAR erasure user_id уже обнулён, и legal-hold relevance
// потеряна).
//
// exceptUserIDs nil / пустой → старое поведение (backward compat
// для callers до PR-L2).
//
// Используется enterprise audit-purge scheduler: перед каждым
// tick'ом scheduler читает `SELECT target_user_id FROM legal_holds
// WHERE is_active = true` и передаёт список сюда. Core CLI
// `cmd/audit-purge` продолжает вызывать backward-compat
// `PurgeOlderThan` (Core scope — нет legal_holds таблицы).
func (r *Repository) PurgeOlderThanExcept(ctx context.Context, cutoff time.Time, chunkSize int, exceptUserIDs []string) (int, error) {
	if chunkSize <= 0 {
		return 0, fmt.Errorf("purge: chunkSize must be > 0, got %d", chunkSize)
	}
	useExcept := len(exceptUserIDs) > 0
	total := 0
	for {
		var (
			res sql.Result
			err error
		)
		if useExcept {
			// pq array — строки UUID передаются как ANY($3::uuid[]).
			// NULL user_id остаются eligible (они уже erased).
			res, err = r.db.ExecContext(ctx,
				`DELETE FROM audit_logs WHERE id IN (
					SELECT id FROM audit_logs
					WHERE created_at < $1
					  AND (user_id IS NULL OR NOT (user_id::text = ANY($3)))
					LIMIT $2
				)`, cutoff, chunkSize, uuidArrayLiteral(exceptUserIDs))
		} else {
			res, err = r.db.ExecContext(ctx,
				`DELETE FROM audit_logs WHERE id IN (
					SELECT id FROM audit_logs WHERE created_at < $1 LIMIT $2
				)`, cutoff, chunkSize)
		}
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

// uuidArrayLiteral — PR-L2 helper. Конвертирует []string в
// Postgres text[] literal ({id1,id2,...}). Используется в
// PurgeOlderThanExcept для передачи exceptUserIDs как параметр
// ANY(). Избегаем зависимости от pq.Array, чтобы минимизировать
// surface для mock'ов.
func uuidArrayLiteral(ids []string) string {
	if len(ids) == 0 {
		return "{}"
	}
	// В postgres text[] literal элементы quoted если содержат
	// спецсимволы. UUID'ы безопасны (dash+hex), но обернём
	// для будущей форсc (если operator случайно положит
	// non-UUID в target_user_id).
	var b []byte
	b = append(b, '{')
	for i, id := range ids {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '"')
		for _, ch := range id {
			if ch == '"' || ch == '\\' {
				b = append(b, '\\')
			}
			b = append(b, byte(ch))
		}
		b = append(b, '"')
	}
	b = append(b, '}')
	return string(b)
}

// PurgeAndRecord — W2.5: truly atomic chunked delete + chained evidence.
// All DELETEs and the audit_purge_runs INSERT run inside ONE transaction.
//
// Contract:
//   - Either ALL deleted rows AND the evidence row commit together.
//   - Or everything rolls back: no deleted rows without evidence row,
//     no evidence row without deleted rows.
//
// Trade-off: the tx is held open for the duration of the delete loop.
// For CLI purge and the admin_event_logs scheduler this is acceptable:
// both are infrequent operator/scheduler operations, not hot-path.
// The coordinated hold-aware purge (PurgeOlderThanRespectingHoldsAndRecordRun)
// was already tx-based from the start.
func (r *Repository) PurgeAndRecord(ctx context.Context, cutoff time.Time, chunkSize int, target string) (int, error) {
	if chunkSize <= 0 {
		return 0, fmt.Errorf("purge: chunkSize must be > 0, got %d", chunkSize)
	}
	if target == "" {
		target = PurgeTargetAuditLogs
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("purge: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	const q = `DELETE FROM audit_logs WHERE id IN (
		SELECT id FROM audit_logs WHERE created_at < $1 LIMIT $2
	)`
	total := 0
	for {
		res, err := tx.ExecContext(ctx, q, cutoff, chunkSize)
		if err != nil {
			return 0, fmt.Errorf("purge exec: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("purge RowsAffected: %w", err)
		}
		total += int(n)
		if n < int64(chunkSize) {
			break
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
	}

	if err := r.recordPurgeRunChained(ctx, tx, cutoff, total, target); err != nil {
		return 0, fmt.Errorf("purge record run: %w", err)
	}
	return total, tx.Commit()
}

// RecordPurgeRunTx — W2.3: записывает chained audit_purge_runs row
// внутри уже открытой транзакции. Используется cross-repo atomic purge
// (например, adminaudit DELETE + audit.RecordPurgeRunTx в shared tx).
// Caller открывает tx и отвечает за Commit/Rollback.
func (r *Repository) RecordPurgeRunTx(ctx context.Context, tx *sql.Tx, cutoff time.Time, rowsDeleted int, target string) error {
	if target == "" {
		target = PurgeTargetAuditLogs
	}
	return r.recordPurgeRunChained(ctx, tx, cutoff, rowsDeleted, target)
}

// RecordPurgeRun сохраняет запись о завершённом purge-run для указанной
// target-таблицы ("audit_logs" | "admin_event_logs"). Вызывающий может
// передать "" — интерпретируется как audit_logs (backward compat для
// call-site'ов до PR-D.1).
//
// PR-W2.1: если chainSecret установлен, пишет chained INSERT в короткой
// транзакции (симметрично coordinated purge в retention_hold.go).
func (r *Repository) RecordPurgeRun(ctx context.Context, cutoff time.Time, rowsDeleted int, target string) error {
	if target == "" {
		target = PurgeTargetAuditLogs
	}
	if len(r.chainSecret) == 0 {
		_, err := r.db.ExecContext(ctx,
			`INSERT INTO audit_purge_runs (cutoff, rows_deleted, completed_at, target)
			 VALUES ($1, $2, now(), $3)`,
			cutoff, rowsDeleted, target)
		if err != nil {
			return fmt.Errorf("record purge run: %w", err)
		}
		return nil
	}
	// Chain path: short tx for advisory lock + chain INSERT.
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("record purge run chain: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := r.recordPurgeRunChained(ctx, tx, cutoff, rowsDeleted, target); err != nil {
		return err
	}
	return tx.Commit()
}

// LastPurgeRun возвращает последний завершённый purge для target'а.
// target="" → audit_logs (default). Nil result → ещё ни разу не purge'или
// эту target-таблицу.
//
// PR-W2.1: ORDER BY seq_no DESC NULLS LAST tiebreaker чтобы
// не было нодетерминизма когда несколько rows имеют один started_at
// (в одной PG-транзакции DEFAULT now() одинаков).
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
		 ORDER BY started_at DESC, seq_no DESC NULLS LAST LIMIT 1`, target).
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

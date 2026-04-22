//go:build enterprise

// Package legalholdcoord — PR-L3 shared coordination для
// apply_hold и retention-aware audit purge. Обе операции берут
// один и тот же `pg_advisory_xact_lock`, что даёт commit-order
// guarantee:
//
//   - Если apply_hold закоммитился раньше purge-commit, purge не
//     удалит audit_logs этого user.
//   - Если purge закоммитился раньше apply_hold, удаление допустимо:
//     на момент purge hold ещё не существовал.
//
// Это сильнее, чем best-effort narrowing PR-L2.1/L2.2 (где
// statement-level READ COMMITTED оставлял race-window между
// apply_hold и delete). НО это НЕ "никакой race вообще": гарантия
// строится вокруг commit order, не вокруг времени начала запроса.
//
// Enterprise-only: и apply_hold, и retention-aware purge живут в
// enterprise build. Core CLI `cmd/audit-purge` в coordination не
// участвует (остаётся manual для core-scope deploy'ев).
package legalholdcoord

import (
	"context"
	"database/sql"
	"fmt"
)

// Advisory lock namespace/resource — произвольные int32 константы.
// Они формируют глобальный mutex внутри PG instance (между всеми
// соединениями, которые берут pg_advisory_xact_lock с этими же
// аргументами).
const (
	// AdvisoryLockNamespace — namespace для legal-hold координации.
	// 4201 выбрано как unlikely-collision с другими app'ами в той же
	// БД. Если позже потребуется другой lock (например legal-hold vs
	// legal-purge-wider-scope) — использовать тот же namespace с
	// другим Resource.
	AdvisoryLockNamespace int32 = 4201

	// HoldPurgeResource — mutex между apply_hold и
	// retention-aware audit_logs purge.
	HoldPurgeResource int32 = 1
)

// AcquireHoldPurgeLock берёт `pg_advisory_xact_lock(ns, resource)`
// внутри переданной транзакции. Lock освобождается автоматически
// при COMMIT или ROLLBACK tx — не требует explicit release.
//
// Блокирующий вызов: если concurrent tx держит этот lock,
// текущий ждёт до его commit/rollback. Для scheduler + apply_hold
// это acceptable (scheduler редкий, apply_hold редкий).
func AcquireHoldPurgeLock(ctx context.Context, tx *sql.Tx) error {
	if tx == nil {
		return fmt.Errorf("legalholdcoord: nil tx")
	}
	_, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock($1, $2)`,
		AdvisoryLockNamespace, HoldPurgeResource)
	if err != nil {
		return fmt.Errorf("legalholdcoord: acquire hold-purge lock: %w", err)
	}
	return nil
}

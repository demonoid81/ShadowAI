// Package chain реализует tamper-evident hash chain для audit trail'а
// ShadowAI (PR-W2, RFC docs/rfcs/2026-04-pr-w1-worm-evidence-architecture.md).
//
// Механизм (RFC §7.2 Layer 1):
//   1. pg_advisory_xact_lock(Namespace, tableID) сериализует chain writes
//      per-table в рамках открытой транзакции.
//   2. Читаем prev_row_hash из последней (max seq_no) row FOR UPDATE.
//   3. Вычисляем row_hash = HMAC-SHA256(prev_row_hash || canonical, secret).
//   4. Возвращаем (seqNo из nextval, rowHash) — caller делает INSERT.
//
// Пакет не имеет build-tag'а: может быть импортирован core и enterprise
// packages. Функциональность включается только если secret != "".
// При пустом secret AcquireSlot возвращает (0, nil, nil) — chain disabled
// path. Caller должен explicit'но проверить (seqNo == 0) и пропустить
// chain fields при INSERT.
package chain

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
)

// pg_advisory_lock namespace для chain writes. Distinct от
// legalholdcoord (4201) чтобы не блокировать друг друга.
const Namespace = 4202

// TableID constants для pg_advisory_xact_lock second arg.
// Каждая таблица с chain fields получает свой ID.
const (
	TableAuditLogs       = 1
	TableAdminEventLogs  = 2
	TableLegalHoldEvents = 3
	TableAuditPurgeRuns  = 4
)

// Sequence names — используются в nextval() при INSERT.
const (
	SeqAuditLogs       = "audit_logs_chain_seq"
	SeqAdminEventLogs  = "admin_event_logs_chain_seq"
	SeqLegalHoldEvents = "legal_hold_events_chain_seq"
	SeqAuditPurgeRuns  = "audit_purge_runs_chain_seq"
)

// initialHash — prev_hash для первой row в таблице (chain anchor point).
// 32 нулевых байта: фиксированное известное значение, не секрет.
var initialHash = make([]byte, 32)

// AcquireSlot захватывает advisory lock на table, читает текущий chain
// tip (prev_row_hash) и вычисляет (nextSeqNo, rowHash) для следующего INSERT.
//
// Должен вызываться ВНУТРИ открытой транзакции tx — advisory lock
// освобождается при commit/rollback этой транзакции.
//
// Параметры:
//   tipTable — имя таблицы для tip lookup ("audit_logs", etc.)
//   seqName  — имя PostgreSQL SEQUENCE для nextval()
//   canonical — v1|... canonical представление строки (package chain/canonical.go)
//   secret   — AUDIT_CHAIN_SECRET в байтах. Пустой → chain disabled.
//
// Возвращает:
//   seqNo == 0 и rowHash == nil при secret == "" (chain disabled — caller skips fields).
//   error при DB failure (caller должен rollback).
func AcquireSlot(ctx context.Context, tx *sql.Tx, tableID int, tipTable, seqName, canonical string, secret []byte) (seqNo int64, rowHash []byte, err error) {
	if len(secret) == 0 {
		// Chain disabled. Caller проверяет (seqNo == 0) и пропускает поля.
		return 0, nil, nil
	}

	// 1. Advisory lock serializes concurrent chain writes for this table.
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock($1, $2)`, Namespace, tableID); err != nil {
		return 0, nil, fmt.Errorf("chain: acquire lock table=%s: %w", tipTable, err)
	}

	// 2. Read current chain tip (prev_hash). FOR UPDATE locks the tip row
	//    against concurrent update from another session holding advisory lock.
	//    ErrNoRows = first row in table → use initialHash.
	var prevHash []byte
	err = tx.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT row_hash FROM %s
			WHERE seq_no = (SELECT max(seq_no) FROM %s WHERE row_hash IS NOT NULL)
			FOR UPDATE`, tipTable, tipTable)).Scan(&prevHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, nil, fmt.Errorf("chain: read tip table=%s: %w", tipTable, err)
	}
	if errors.Is(err, sql.ErrNoRows) || len(prevHash) == 0 {
		prevHash = initialHash
	}

	// 3. Compute row_hash = HMAC-SHA256(prev_hash || canonical, secret).
	mac := hmac.New(sha256.New, secret)
	mac.Write(prevHash)
	mac.Write([]byte(canonical))
	rowHash = mac.Sum(nil)

	// 4. Get next seq_no from PG SEQUENCE.
	if err := tx.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT nextval('%s')`, seqName)).Scan(&seqNo); err != nil {
		return 0, nil, fmt.Errorf("chain: nextval seq=%s: %w", seqName, err)
	}

	return seqNo, rowHash, nil
}

// Verify recomputes row_hash for a given (prevHash, canonical) pair and
// compares with stored hash. Returns true если совпадает.
// Используется в cmd/audit-verify.
func Verify(prevHash []byte, canonical string, secret, storedHash []byte) bool {
	if len(prevHash) == 0 {
		prevHash = initialHash
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(prevHash)
	mac.Write([]byte(canonical))
	expected := mac.Sum(nil)
	return hmac.Equal(expected, storedHash)
}

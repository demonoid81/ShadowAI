//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package legalhold

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shadowai/backend/internal/legalholdcoord"
)

// ErrAlreadyActive — DB unique violation при попытке создать
// второй active hold на одного user'а.
var ErrAlreadyActive = errors.New("legalhold: user already has active hold")

// ErrNotFound — hold по ID не найден (для Release).
var ErrNotFound = errors.New("legalhold: hold not found")

// ErrNotActive — попытка release уже released hold'а. Идемпотентно
// трактуем как "already released" в handler'е, но на repo-уровне
// даём явную ошибку.
//
// PR-L2.3 note: ранее ErrNotActive также возвращалась для pending
// status. Это collapse'ило семантику "pending нельзя release" в
// "hold уже released 200". Теперь для pending возвращается
// ErrPendingNotReleasable — отдельный non-idempotent error, чтобы
// handler мог вернуть 409 "use reject" вместо ложного 200.
var ErrNotActive = errors.New("legalhold: hold is not active")

// ErrPendingNotReleasable — PR-L2.3: Release вызван на pending hold.
// Это НЕ идемпотентность (hold ещё не был active), а contract
// violation — pending должен отменяться через Reject. Handler
// мапит это в 409 с подсказкой operator'у.
var ErrPendingNotReleasable = errors.New("legalhold: hold is pending, use reject to cancel")

// ErrNotPending — approve/reject на hold, у которого уже не
// pending (approved или released). L2.3.
var ErrNotPending = errors.New("legalhold: hold is not pending")

// ErrSelfApproval — 4-eyes policy violation: approver == creator.
var ErrSelfApproval = errors.New("legalhold: approver must differ from creator")

type PGRepository struct {
	db *sql.DB
}

func NewPGRepository(db *sql.DB) *PGRepository {
	return &PGRepository{db: db}
}

// Create вставляет новую pending запись (L2.3: 4-eyes).
// Pending hold ЕЩЁ НЕ блокирует DSAR и не защищает audit от
// purge. Для активации требуется Approve другим admin.
//
// Если у user уже есть pending или active hold — возвращает
// ErrAlreadyActive (DB partial-unique violation: один
// блокирующий hold per user).
//
// PR-L3: выполняется в tx под
// `legalholdcoord.AcquireHoldPurgeLock`.
//   Commit-order guarantee с retention-aware audit purge.
//   (Pending hold тоже берёт lock — defensive, хотя
//   purge-SQL проверяет только status='active').
func (r *PGRepository) Create(ctx context.Context, h *Hold) (*Hold, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("legalhold: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := legalholdcoord.AcquireHoldPurgeLock(ctx, tx); err != nil {
		return nil, err
	}

	const q = `INSERT INTO legal_holds
	    (target_user_id, case_ref, reason, created_by, status, is_active)
	    VALUES ($1, $2, $3, $4, 'pending', false)
	    RETURNING id, created_at`
	var (
		id        string
		createdAt time.Time
	)
	var actor any
	if h.CreatedBy != nil && *h.CreatedBy != "" {
		actor = *h.CreatedBy
	}
	if err := tx.QueryRowContext(ctx, q, h.TargetUserID, h.CaseRef, h.Reason, actor).
		Scan(&id, &createdAt); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrAlreadyActive
		}
		return nil, fmt.Errorf("legalhold: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("legalhold: commit: %w", err)
	}
	h.ID = id
	h.CreatedAt = createdAt
	h.Status = StatusPending
	h.IsActive = false
	return h, nil
}

// Approve переводит pending hold в active. approverID должен
// отличаться от hold.CreatedBy (4-eyes policy).
//
// L2.3: ТОЛЬКО на этой операции hold начинает блокировать DSAR
// и участвовать в purge-protection. Pending hold — no-op для
// runtime enforcement.
//
// Выполняется в tx под coord lock — commit-order guarantee
// аналогично Create.
//
// Errors:
//   - ErrNotFound — hold.id отсутствует.
//   - ErrNotPending — hold уже approved или released.
//   - ErrSelfApproval — approverID == creator (4-eyes violation).
func (r *PGRepository) Approve(ctx context.Context, id, approverID string) (*Hold, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	if approverID == "" {
		return nil, fmt.Errorf("legalhold: approver id required")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("legalhold: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := legalholdcoord.AcquireHoldPurgeLock(ctx, tx); err != nil {
		return nil, err
	}

	// Lock row + read current state + creator.
	var (
		status    string
		createdBy sql.NullString
	)
	err = tx.QueryRowContext(ctx,
		`SELECT status, created_by FROM legal_holds WHERE id = $1 FOR UPDATE`, id,
	).Scan(&status, &createdBy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("legalhold: approve lookup: %w", err)
	}
	if status != string(StatusPending) {
		return nil, ErrNotPending
	}
	// 4-eyes: approver != creator.
	if createdBy.Valid && createdBy.String == approverID {
		return nil, ErrSelfApproval
	}

	const upd = `UPDATE legal_holds
	    SET status = 'active', is_active = true,
	        approved_at = now(), approved_by = $2
	    WHERE id = $1
	    RETURNING target_user_id, case_ref, reason, created_by,
	              created_at, approved_at, approved_by, released_at,
	              released_by, status, is_active`
	var (
		h          Hold
		createdBy2 sql.NullString
		approvedAt sql.NullTime
		approvedBy sql.NullString
		releasedAt sql.NullTime
		releasedBy sql.NullString
	)
	if err := tx.QueryRowContext(ctx, upd, id, approverID).Scan(
		&h.TargetUserID, &h.CaseRef, &h.Reason, &createdBy2,
		&h.CreatedAt, &approvedAt, &approvedBy, &releasedAt,
		&releasedBy, &h.Status, &h.IsActive,
	); err != nil {
		return nil, fmt.Errorf("legalhold: approve update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("legalhold: approve commit: %w", err)
	}
	h.ID = id
	if createdBy2.Valid {
		s := createdBy2.String
		h.CreatedBy = &s
	}
	if approvedAt.Valid {
		t := approvedAt.Time
		h.ApprovedAt = &t
	}
	if approvedBy.Valid {
		s := approvedBy.String
		h.ApprovedBy = &s
	}
	if releasedAt.Valid {
		t := releasedAt.Time
		h.ReleasedAt = &t
	}
	if releasedBy.Valid {
		s := releasedBy.String
		h.ReleasedBy = &s
	}
	return &h, nil
}

// Reject переводит pending hold в released (rejected). Этот
// endpoint для отмены pending hold'а (tech-walls: creator решил
// не отправлять на approve, или legal решил не apply'ить).
//
// Approver check (!= creator) НЕ применяется для Reject — сам
// creator может cancel'нуть свой pending. Это отличается от
// Approve.
//
// Errors: ErrNotFound, ErrNotPending.
func (r *PGRepository) Reject(ctx context.Context, id, rejectorID string) (*Hold, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("legalhold: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := legalholdcoord.AcquireHoldPurgeLock(ctx, tx); err != nil {
		return nil, err
	}

	var status string
	err = tx.QueryRowContext(ctx,
		`SELECT status FROM legal_holds WHERE id = $1 FOR UPDATE`, id,
	).Scan(&status)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("legalhold: reject lookup: %w", err)
	}
	if status != string(StatusPending) {
		return nil, ErrNotPending
	}

	var actor any
	if rejectorID != "" {
		actor = rejectorID
	}
	const upd = `UPDATE legal_holds
	    SET status = 'released', is_active = false,
	        released_at = now(), released_by = $2
	    WHERE id = $1
	    RETURNING target_user_id, case_ref, reason, created_by,
	              created_at, approved_at, approved_by, released_at,
	              released_by, status, is_active`
	var (
		h          Hold
		createdBy  sql.NullString
		approvedAt sql.NullTime
		approvedBy sql.NullString
		releasedAt sql.NullTime
		releasedBy sql.NullString
	)
	if err := tx.QueryRowContext(ctx, upd, id, actor).Scan(
		&h.TargetUserID, &h.CaseRef, &h.Reason, &createdBy,
		&h.CreatedAt, &approvedAt, &approvedBy, &releasedAt,
		&releasedBy, &h.Status, &h.IsActive,
	); err != nil {
		return nil, fmt.Errorf("legalhold: reject update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("legalhold: reject commit: %w", err)
	}
	h.ID = id
	if createdBy.Valid {
		s := createdBy.String
		h.CreatedBy = &s
	}
	if approvedAt.Valid {
		t := approvedAt.Time
		h.ApprovedAt = &t
	}
	if approvedBy.Valid {
		s := approvedBy.String
		h.ApprovedBy = &s
	}
	if releasedAt.Valid {
		t := releasedAt.Time
		h.ReleasedAt = &t
	}
	if releasedBy.Valid {
		s := releasedBy.String
		h.ReleasedBy = &s
	}
	return &h, nil
}

// Release — переводит hold в inactive. Идемпотентно выбирается на
// handler-level: если is_active=false, repo вернёт ErrNotActive,
// handler превращает в "already_released" response.
func (r *PGRepository) Release(ctx context.Context, id, releasedBy string) (*Hold, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	// L2.3: Release работает только на active hold (не на pending).
	// Pending cancel идёт через Reject.
	const q = `UPDATE legal_holds
	    SET status = 'released', is_active = false,
	        released_at = now(), released_by = $2
	    WHERE id = $1 AND status = 'active'
	    RETURNING target_user_id, case_ref, reason, created_by, created_at,
	              approved_at, approved_by, released_at, released_by, status, is_active`
	var (
		h          Hold
		createdBy  sql.NullString
		approvedAt sql.NullTime
		approvedBy sql.NullString
		releasedAt sql.NullTime
		releasedOp sql.NullString
	)
	var actor any
	if releasedBy != "" {
		actor = releasedBy
	}
	err := r.db.QueryRowContext(ctx, q, id, actor).Scan(
		&h.TargetUserID, &h.CaseRef, &h.Reason, &createdBy,
		&h.CreatedAt, &approvedAt, &approvedBy,
		&releasedAt, &releasedOp, &h.Status, &h.IsActive,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// либо id не существует, либо hold не active.
			return r.checkExistsInactive(ctx, id)
		}
		return nil, fmt.Errorf("legalhold: update: %w", err)
	}
	h.ID = id
	if createdBy.Valid {
		s := createdBy.String
		h.CreatedBy = &s
	}
	if approvedAt.Valid {
		t := approvedAt.Time
		h.ApprovedAt = &t
	}
	if approvedBy.Valid {
		s := approvedBy.String
		h.ApprovedBy = &s
	}
	if releasedAt.Valid {
		t := releasedAt.Time
		h.ReleasedAt = &t
	}
	if releasedOp.Valid {
		s := releasedOp.String
		h.ReleasedBy = &s
	}
	return &h, nil
}

// checkExistsInactive — используется Release для различения
// not-found от already-released / still-pending.
func (r *PGRepository) checkExistsInactive(ctx context.Context, id string) (*Hold, error) {
	var status string
	err := r.db.QueryRowContext(ctx,
		`SELECT status FROM legal_holds WHERE id = $1`, id).Scan(&status)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("legalhold: existence check: %w", err)
	}
	switch status {
	case string(StatusPending):
		// Release на pending НЕ идемпотентен — hold ещё не был active.
		// Handler вернёт 409 с указанием использовать reject.
		return nil, ErrPendingNotReleasable
	case string(StatusReleased):
		// Идемпотентность: hold был active → released; повторный
		// Release безопасно возвращает 200 через ErrNotActive path.
		return nil, ErrNotActive
	default:
		// active, но UPDATE не нашёл — race с concurrent release.
		return nil, ErrNotActive
	}
}

// ActiveUserIDs — PR-L2 + L2.3: bulk lookup для retention-aware
// audit purge. Возвращает target_user_id только тех записей, где
// status='active' (pending НЕ защищает от purge до approve).
func (r *PGRepository) ActiveUserIDs(ctx context.Context) ([]string, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT target_user_id::text FROM legal_holds WHERE status = 'active'`)
	if err != nil {
		return nil, fmt.Errorf("legalhold: active user ids: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// HasActiveHold — hot-path check для ErasureService.
// L2.3: только status='active' блокирует. Pending НЕ блокирует
// DSAR — creator может пересмотреть до approve.
func (r *PGRepository) HasActiveHold(ctx context.Context, userID string) (bool, error) {
	if r == nil || r.db == nil {
		return false, fmt.Errorf("legalhold: repo not configured")
	}
	var exists bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS(
		    SELECT 1 FROM legal_holds
		    WHERE target_user_id = $1 AND status = 'active'
		)`, userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("legalhold: has active: %w", err)
	}
	return exists, nil
}

// List возвращает все hold'ы, сортировка: active first, потом
// по created_at DESC. Для v1 без pagination.
func (r *PGRepository) List(ctx context.Context) ([]Hold, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, target_user_id, case_ref, reason, created_by,
		    created_at, approved_at, approved_by,
		    released_at, released_by, status, is_active
		 FROM legal_holds
		 ORDER BY
		    CASE status
		        WHEN 'active' THEN 0
		        WHEN 'pending' THEN 1
		        ELSE 2
		    END,
		    created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("legalhold: list: %w", err)
	}
	defer rows.Close()
	var out []Hold
	for rows.Next() {
		var h Hold
		var createdBy, approvedByN, releasedBy sql.NullString
		var approvedAtN, releasedAt sql.NullTime
		if err := rows.Scan(
			&h.ID, &h.TargetUserID, &h.CaseRef, &h.Reason, &createdBy,
			&h.CreatedAt, &approvedAtN, &approvedByN,
			&releasedAt, &releasedBy, &h.Status, &h.IsActive,
		); err != nil {
			return nil, err
		}
		if createdBy.Valid {
			s := createdBy.String
			h.CreatedBy = &s
		}
		if approvedAtN.Valid {
			t := approvedAtN.Time
			h.ApprovedAt = &t
		}
		if approvedByN.Valid {
			s := approvedByN.String
			h.ApprovedBy = &s
		}
		if releasedAt.Valid {
			t := releasedAt.Time
			h.ReleasedAt = &t
		}
		if releasedBy.Valid {
			s := releasedBy.String
			h.ReleasedBy = &s
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// isUniqueViolation — PostgreSQL 23505 unique_violation. Используется
// partial-unique index idx_legal_holds_active_per_user. Без
// SQLSTATE-awareness fallback'ится на substring match.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	// pq-specific: err.Error() содержит "pq: duplicate key value
	// violates unique constraint" или "23505". Portable через
	// substring check.
	msg := err.Error()
	return strings.Contains(msg, "23505") ||
		strings.Contains(msg, "duplicate key value")
}

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
var ErrNotActive = errors.New("legalhold: hold is not active")

type PGRepository struct {
	db *sql.DB
}

func NewPGRepository(db *sql.DB) *PGRepository {
	return &PGRepository{db: db}
}

// Create вставляет новую active запись. Если у user уже есть
// active hold — возвращает ErrAlreadyActive (DB partial-unique
// violation).
//
// PR-L3: выполняется в tx под
// `legalholdcoord.AcquireHoldPurgeLock`. Это даёт commit-order
// guarantee с retention-aware audit purge:
//   - apply_hold commit → purge commit: purge видит hold, rows
//     защищены.
//   - purge commit → apply_hold commit: rows user'а могли
//     удалиться (hold ещё не существовал на момент purge-commit'а —
//     допустимое поведение).
func (r *PGRepository) Create(ctx context.Context, h *Hold) (*Hold, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("legalhold: begin tx: %w", err)
	}
	// Defensive rollback. Commit ниже; defer rollback на уже
	// committed tx — no-op в lib/pq.
	defer func() { _ = tx.Rollback() }()

	if err := legalholdcoord.AcquireHoldPurgeLock(ctx, tx); err != nil {
		return nil, err
	}

	const q = `INSERT INTO legal_holds
	    (target_user_id, case_ref, reason, created_by, is_active)
	    VALUES ($1, $2, $3, $4, true)
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
	h.IsActive = true
	return h, nil
}

// Release — переводит hold в inactive. Идемпотентно выбирается на
// handler-level: если is_active=false, repo вернёт ErrNotActive,
// handler превращает в "already_released" response.
func (r *PGRepository) Release(ctx context.Context, id, releasedBy string) (*Hold, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	const q = `UPDATE legal_holds
	    SET is_active = false, released_at = now(), released_by = $2
	    WHERE id = $1 AND is_active = true
	    RETURNING target_user_id, case_ref, reason, created_by, created_at, released_at, released_by`
	var (
		h          Hold
		createdBy  sql.NullString
		releasedAt sql.NullTime
		releasedOp sql.NullString
	)
	var actor any
	if releasedBy != "" {
		actor = releasedBy
	}
	err := r.db.QueryRowContext(ctx, q, id, actor).Scan(
		&h.TargetUserID, &h.CaseRef, &h.Reason, &createdBy,
		&h.CreatedAt, &releasedAt, &releasedOp,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// либо id не существует, либо hold уже inactive
			return r.checkExistsInactive(ctx, id)
		}
		return nil, fmt.Errorf("legalhold: update: %w", err)
	}
	h.ID = id
	h.IsActive = false
	if createdBy.Valid {
		s := createdBy.String
		h.CreatedBy = &s
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
// not-found от already-released.
func (r *PGRepository) checkExistsInactive(ctx context.Context, id string) (*Hold, error) {
	var isActive bool
	err := r.db.QueryRowContext(ctx,
		`SELECT is_active FROM legal_holds WHERE id = $1`, id).Scan(&isActive)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("legalhold: existence check: %w", err)
	}
	if !isActive {
		return nil, ErrNotActive
	}
	// Недостижимо при нормальном flow: active=true, но UPDATE не
	// нашёл (race с другим release). Возвращаем как not-active
	// для идемпотентности.
	return nil, ErrNotActive
}

// ActiveUserIDs — PR-L2: bulk lookup для retention-aware audit
// purge. Возвращает target_user_id всех is_active=true записей.
// Индекс idx_legal_holds_active_per_user гарантирует, что каждый
// UUID встречается не более одного раза.
func (r *PGRepository) ActiveUserIDs(ctx context.Context) ([]string, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT target_user_id::text FROM legal_holds WHERE is_active = true`)
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
func (r *PGRepository) HasActiveHold(ctx context.Context, userID string) (bool, error) {
	if r == nil || r.db == nil {
		return false, fmt.Errorf("legalhold: repo not configured")
	}
	var exists bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS(
		    SELECT 1 FROM legal_holds
		    WHERE target_user_id = $1 AND is_active = true
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
		    created_at, released_at, released_by, is_active
		 FROM legal_holds
		 ORDER BY is_active DESC, created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("legalhold: list: %w", err)
	}
	defer rows.Close()
	var out []Hold
	for rows.Next() {
		var h Hold
		var createdBy, releasedBy sql.NullString
		var releasedAt sql.NullTime
		if err := rows.Scan(
			&h.ID, &h.TargetUserID, &h.CaseRef, &h.Reason, &createdBy,
			&h.CreatedAt, &releasedAt, &releasedBy, &h.IsActive,
		); err != nil {
			return nil, err
		}
		if createdBy.Valid {
			s := createdBy.String
			h.CreatedBy = &s
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

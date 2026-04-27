//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package legalhold

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings" //nolint:unused
	"time"

	"github.com/google/uuid"
	"github.com/shadowai/backend/internal/chain"
	"github.com/shadowai/backend/internal/domain"
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

// ErrNotReleasePending — PR-L5: ApproveRelease/RejectRelease на hold
// который не в статусе release_pending.
var ErrNotReleasePending = errors.New("legalhold: hold is not in release_pending state")

// ErrSelfReleaseApproval — PR-L5: 4-eyes violation для ApproveRelease:
// approver совпадает с тем, кто запросил release.
var ErrSelfReleaseApproval = errors.New("legalhold: release approver must differ from release requester")

// ErrAlreadyReleasePending — PR-L5: RequestRelease на hold который уже
// в release_pending. Повторный запрос должен быть явным конфликтом,
// не idempotent.
var ErrAlreadyReleasePending = errors.New("legalhold: hold is already awaiting release approval")

type PGRepository struct {
	db          *sql.DB
	chainSecret []byte
}

func NewPGRepository(db *sql.DB) *PGRepository {
	return &PGRepository{db: db}
}

func (r *PGRepository) WithChainSecret(secret string) *PGRepository {
	c := *r
	c.chainSecret = []byte(secret)
	return &c
}

// insertHoldEvent writes a legal_hold_events row inside an existing tx (W2).
// Если chainSecret пустой — chain fields остаются NULL (chain disabled).
func (r *PGRepository) insertHoldEvent(ctx context.Context, tx *sql.Tx, holdID, action, newStatus, actorID string) error {
	eventID := uuid.New().String()
	// W2 fix: захватываем createdAt ОДИН раз до chain write.
	// Используем то же значение в canonical и в INSERT — без этого
	// canonical(time.Now()) при hash и DB DEFAULT now() при INSERT
	// расходятся (разные вызовы time.Now + DB round).
	createdAt := time.Now().UTC()

	var actorArg any
	if actorID != "" {
		actorArg = actorID
	}
	orgID := domain.DefaultOrgID
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(org_id::text, $2) FROM legal_holds WHERE id = $1`,
		holdID, domain.DefaultOrgID).Scan(&orgID); err != nil {
		return fmt.Errorf("legalhold: resolve event org: %w", err)
	}
	canonical := chain.CanonicalLegalHoldEvent(eventID, holdID, action, newStatus, actorID, createdAt.Unix())
	seqNo, rowHash, err := chain.AcquireSlot(ctx, tx,
		chain.TableLegalHoldEvents, "legal_hold_events", chain.SeqLegalHoldEvents,
		canonical, r.chainSecret)
	if err != nil {
		return fmt.Errorf("legalhold chain: acquire slot: %w", err)
	}
	var seqArg any
	var hashArg any
	if seqNo > 0 {
		seqArg = seqNo
		hashArg = rowHash
	}
	// INSERT с явным created_at ($8) — совпадает с canonical.
	_, err = tx.ExecContext(ctx,
		`INSERT INTO legal_hold_events (id, hold_id, action, new_status, actor_id, created_at, seq_no, row_hash, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		eventID, holdID, action, newStatus, actorArg, createdAt, seqArg, hashArg, orgID)
	return err
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
//
//	Гарантия порядка commit для purge аудита с учётом retention.
//	Ожидающий hold тоже берёт lock защитно, хотя
//	purge-SQL проверяет только status='active'.
func (r *PGRepository) Create(ctx context.Context, h *Hold) (*Hold, error) {
	return r.CreateInOrg(ctx, h, h.OrgID)
}

func (r *PGRepository) CreateInOrg(ctx context.Context, h *Hold, orgID string) (*Hold, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
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
	    (target_user_id, case_ref, reason, created_by, status, is_active, org_id)
	    VALUES ($1, $2, $3, $4, 'pending', false, $5)
	    RETURNING id, created_at`
	var (
		id        string
		createdAt time.Time
	)
	var actor any
	if h.CreatedBy != nil && *h.CreatedBy != "" {
		actor = *h.CreatedBy
	}
	if err := tx.QueryRowContext(ctx, q, h.TargetUserID, h.CaseRef, h.Reason, actor, orgID).
		Scan(&id, &createdAt); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrAlreadyActive
		}
		return nil, fmt.Errorf("legalhold: insert: %w", err)
	}
	// PR-W2: write legal_hold_events chain entry before commit.
	creatorID := ""
	if h.CreatedBy != nil {
		creatorID = *h.CreatedBy
	}
	if err := r.insertHoldEvent(ctx, tx, id, "create", "pending", creatorID); err != nil {
		return nil, fmt.Errorf("legalhold: hold event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("legalhold: commit: %w", err)
	}
	h.ID = id
	h.OrgID = orgID
	h.CreatedAt = createdAt
	h.Status = StatusPending
	h.IsActive = false
	return h, nil
}

func (r *PGRepository) ensureHoldInOrg(ctx context.Context, id, orgID string) error {
	if orgID == "" {
		return nil
	}
	var exists bool
	if err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM legal_holds WHERE id = $1 AND org_id = $2)`,
		id, orgID).Scan(&exists); err != nil {
		return fmt.Errorf("legalhold: org scope check: %w", err)
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (r *PGRepository) ApproveInOrg(ctx context.Context, id, approverID, orgID string) (*Hold, error) {
	if err := r.ensureHoldInOrg(ctx, id, orgID); err != nil {
		return nil, err
	}
	return r.Approve(ctx, id, approverID)
}

func (r *PGRepository) RejectInOrg(ctx context.Context, id, rejectorID, orgID string) (*Hold, error) {
	if err := r.ensureHoldInOrg(ctx, id, orgID); err != nil {
		return nil, err
	}
	return r.Reject(ctx, id, rejectorID)
}

func (r *PGRepository) ReleaseInOrg(ctx context.Context, id, requesterID, orgID string) (*Hold, error) {
	if err := r.ensureHoldInOrg(ctx, id, orgID); err != nil {
		return nil, err
	}
	return r.Release(ctx, id, requesterID)
}

func (r *PGRepository) ApproveReleaseInOrg(ctx context.Context, id, approverID, orgID string) (*Hold, error) {
	if err := r.ensureHoldInOrg(ctx, id, orgID); err != nil {
		return nil, err
	}
	return r.ApproveRelease(ctx, id, approverID)
}

func (r *PGRepository) RejectReleaseInOrg(ctx context.Context, id, rejectorID, orgID string) (*Hold, error) {
	if err := r.ensureHoldInOrg(ctx, id, orgID); err != nil {
		return nil, err
	}
	return r.RejectRelease(ctx, id, rejectorID)
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
	if err := r.insertHoldEvent(ctx, tx, id, "approve", "active", approverID); err != nil {
		return nil, fmt.Errorf("legalhold: approve hold event: %w", err)
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
	if err := r.insertHoldEvent(ctx, tx, id, "reject", "released", rejectorID); err != nil {
		return nil, fmt.Errorf("legalhold: reject hold event: %w", err)
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

// Release — PR-L5 BREAKING CHANGE: теперь RequestRelease.
// active → release_pending (не immediate active → released).
//
// Идемпотентность:
//   - already release_pending → ErrAlreadyReleasePending (409, explicit conflict)
//   - already released        → ErrNotActive (200 "already_released")
//   - pending                 → ErrPendingNotReleasable (409, use reject)
func (r *PGRepository) Release(ctx context.Context, id, requesterID string) (*Hold, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("legalhold: request_release begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Lock row + read current state.
	var status string
	err = tx.QueryRowContext(ctx,
		`SELECT status FROM legal_holds WHERE id = $1 FOR UPDATE`, id,
	).Scan(&status)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("legalhold: request_release lookup: %w", err)
	}
	switch Status(status) {
	case StatusPending:
		return nil, ErrPendingNotReleasable
	case StatusReleasePending:
		return nil, ErrAlreadyReleasePending
	case StatusReleased:
		return nil, ErrNotActive
	case StatusActive:
		// proceed
	default:
		return nil, ErrNotActive
	}

	var actor any
	if requesterID != "" {
		actor = requesterID
	}
	const q = `UPDATE legal_holds
	    SET status = 'release_pending',
	        release_requested_at = now(), release_requested_by = $2
	    WHERE id = $1
	    RETURNING target_user_id, case_ref, reason, created_by, created_at,
	              approved_at, approved_by, released_at, released_by,
	              release_requested_at, release_requested_by, status, is_active`
	var (
		h            Hold
		createdBy    sql.NullString
		approvedAt   sql.NullTime
		approvedBy   sql.NullString
		releasedAt   sql.NullTime
		releasedBy   sql.NullString
		releaseReqAt sql.NullTime
		releaseReqBy sql.NullString
	)
	if err := tx.QueryRowContext(ctx, q, id, actor).Scan(
		&h.TargetUserID, &h.CaseRef, &h.Reason, &createdBy,
		&h.CreatedAt, &approvedAt, &approvedBy,
		&releasedAt, &releasedBy,
		&releaseReqAt, &releaseReqBy,
		&h.Status, &h.IsActive,
	); err != nil {
		return nil, fmt.Errorf("legalhold: request_release update: %w", err)
	}
	if err := r.insertHoldEvent(ctx, tx, id, "request_release", "release_pending", requesterID); err != nil {
		return nil, fmt.Errorf("legalhold: request_release hold event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("legalhold: request_release commit: %w", err)
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
	if releaseReqAt.Valid {
		t := releaseReqAt.Time
		h.ReleaseRequestedAt = &t
	}
	if releaseReqBy.Valid {
		s := releaseReqBy.String
		h.ReleaseRequestedBy = &s
	}
	return &h, nil
}

// ApproveRelease — PR-L5: 4-eyes перевод release_pending → released.
// approverID должен отличаться от release_requested_by.
func (r *PGRepository) ApproveRelease(ctx context.Context, id, approverID string) (*Hold, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	if approverID == "" {
		return nil, fmt.Errorf("legalhold: approver id required")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("legalhold: approve_release begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := legalholdcoord.AcquireHoldPurgeLock(ctx, tx); err != nil {
		return nil, err
	}

	var (
		status       string
		releaseReqBy sql.NullString
	)
	err = tx.QueryRowContext(ctx,
		`SELECT status, release_requested_by FROM legal_holds WHERE id = $1 FOR UPDATE`, id,
	).Scan(&status, &releaseReqBy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("legalhold: approve_release lookup: %w", err)
	}
	if Status(status) != StatusReleasePending {
		return nil, ErrNotReleasePending
	}
	// 4-eyes: approver != requester.
	if releaseReqBy.Valid && releaseReqBy.String == approverID {
		return nil, ErrSelfReleaseApproval
	}

	var actor any
	if approverID != "" {
		actor = approverID
	}
	const upd = `UPDATE legal_holds
	    SET status = 'released', is_active = false,
	        released_at = now(), released_by = $2
	    WHERE id = $1
	    RETURNING target_user_id, case_ref, reason, created_by, created_at,
	              approved_at, approved_by, released_at, released_by,
	              release_requested_at, release_requested_by, status, is_active`
	h, err := r.scanHoldFull(tx.QueryRowContext(ctx, upd, id, actor))
	if err != nil {
		return nil, fmt.Errorf("legalhold: approve_release update: %w", err)
	}
	if err := r.insertHoldEvent(ctx, tx, id, "approve_release", "released", approverID); err != nil {
		return nil, fmt.Errorf("legalhold: approve_release hold event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("legalhold: approve_release commit: %w", err)
	}
	h.ID = id
	return h, nil
}

// RejectRelease — PR-L5: перевод release_pending → active (release rejected).
func (r *PGRepository) RejectRelease(ctx context.Context, id, rejectorID string) (*Hold, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("legalhold: reject_release begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var status string
	err = tx.QueryRowContext(ctx,
		`SELECT status FROM legal_holds WHERE id = $1 FOR UPDATE`, id,
	).Scan(&status)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("legalhold: reject_release lookup: %w", err)
	}
	if Status(status) != StatusReleasePending {
		return nil, ErrNotReleasePending
	}

	var actor any
	if rejectorID != "" {
		actor = rejectorID
	}
	const upd = `UPDATE legal_holds
	    SET status = 'active', is_active = true,
	        release_requested_at = NULL, release_requested_by = NULL,
	        released_at = now(), released_by = $2
	    WHERE id = $1
	    RETURNING target_user_id, case_ref, reason, created_by, created_at,
	              approved_at, approved_by, released_at, released_by,
	              release_requested_at, release_requested_by, status, is_active`
	h, err := r.scanHoldFull(tx.QueryRowContext(ctx, upd, id, actor))
	if err != nil {
		return nil, fmt.Errorf("legalhold: reject_release update: %w", err)
	}
	if err := r.insertHoldEvent(ctx, tx, id, "reject_release", "active", rejectorID); err != nil {
		return nil, fmt.Errorf("legalhold: reject_release hold event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("legalhold: reject_release commit: %w", err)
	}
	h.ID = id
	// released_by carries the rejector in this transition; clear it since hold is active again.
	h.ReleasedAt = nil
	h.ReleasedBy = nil
	_ = actor
	return h, nil
}

// PendingOlderThan — PR-L5: SLA visibility query.
// Возвращает pending holds созданные более threshold назад.
func (r *PGRepository) PendingOlderThan(ctx context.Context, threshold time.Duration) ([]Hold, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	cutoff := time.Now().UTC().Add(-threshold)
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, target_user_id, case_ref, reason, created_by,
		    created_at, approved_at, approved_by,
		    released_at, released_by, status, is_active,
		    release_requested_at, release_requested_by
		 FROM legal_holds
		 WHERE status = 'pending' AND created_at < $1
		 ORDER BY created_at ASC`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("legalhold: pending_older_than: %w", err)
	}
	defer rows.Close()
	return r.scanHolds(rows)
}

func (r *PGRepository) PendingOlderThanInOrg(ctx context.Context, threshold time.Duration, orgID string) ([]Hold, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	if orgID == "" {
		return r.PendingOlderThan(ctx, threshold)
	}
	cutoff := time.Now().UTC().Add(-threshold)
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, target_user_id, case_ref, reason, created_by,
		    created_at, approved_at, approved_by,
		    released_at, released_by, status, is_active,
		    release_requested_at, release_requested_by
		 FROM legal_holds
		 WHERE status = 'pending' AND created_at < $1 AND org_id = $2
		 ORDER BY created_at ASC`, cutoff, orgID)
	if err != nil {
		return nil, fmt.Errorf("legalhold: pending_older_than scoped: %w", err)
	}
	defer rows.Close()
	return r.scanHolds(rows)
}

// scanHoldFull — helper для single-row scans with all columns.
func (r *PGRepository) scanHoldFull(row *sql.Row) (*Hold, error) {
	var (
		h            Hold
		createdBy    sql.NullString
		approvedAt   sql.NullTime
		approvedBy   sql.NullString
		releasedAt   sql.NullTime
		releasedBy   sql.NullString
		releaseReqAt sql.NullTime
		releaseReqBy sql.NullString
	)
	if err := row.Scan(
		&h.TargetUserID, &h.CaseRef, &h.Reason, &createdBy,
		&h.CreatedAt, &approvedAt, &approvedBy,
		&releasedAt, &releasedBy,
		&releaseReqAt, &releaseReqBy,
		&h.Status, &h.IsActive,
	); err != nil {
		return nil, err
	}
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
	if releaseReqAt.Valid {
		t := releaseReqAt.Time
		h.ReleaseRequestedAt = &t
	}
	if releaseReqBy.Valid {
		s := releaseReqBy.String
		h.ReleaseRequestedBy = &s
	}
	return &h, nil
}

// scanHolds — helper for multi-row scans.
func (r *PGRepository) scanHolds(rows *sql.Rows) ([]Hold, error) {
	var out []Hold
	for rows.Next() {
		var (
			h            Hold
			createdBy    sql.NullString
			approvedAt   sql.NullTime
			approvedBy   sql.NullString
			releasedAt   sql.NullTime
			releasedBy   sql.NullString
			releaseReqAt sql.NullTime
			releaseReqBy sql.NullString
		)
		if err := rows.Scan(
			&h.ID, &h.TargetUserID, &h.CaseRef, &h.Reason, &createdBy,
			&h.CreatedAt, &approvedAt, &approvedBy,
			&releasedAt, &releasedBy, &h.Status, &h.IsActive,
			&releaseReqAt, &releaseReqBy,
		); err != nil {
			return nil, err
		}
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
		if releaseReqAt.Valid {
			t := releaseReqAt.Time
			h.ReleaseRequestedAt = &t
		}
		if releaseReqBy.Valid {
			s := releaseReqBy.String
			h.ReleaseRequestedBy = &s
		}
		out = append(out, h)
	}
	return out, rows.Err()
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

// ActiveUserIDs — PR-L2 + L2.3 + L5: bulk lookup для retention-aware
// audit purge. Возвращает target_user_id для status IN ('active',
// 'release_pending'). release_pending держит purge protection до
// ApproveRelease.
func (r *PGRepository) ActiveUserIDs(ctx context.Context) ([]string, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT target_user_id::text FROM legal_holds WHERE status IN ('active', 'release_pending')`)
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
// PR-L5: блокирует для status IN ('active', 'release_pending').
// release_pending остаётся legally binding до ApproveRelease.
// pending НЕ блокирует (ещё не approve'нут).
func (r *PGRepository) HasActiveHold(ctx context.Context, userID string) (bool, error) {
	if r == nil || r.db == nil {
		return false, fmt.Errorf("legalhold: repo not configured")
	}
	var exists bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS(
		    SELECT 1 FROM legal_holds
		    WHERE target_user_id = $1 AND status IN ('active', 'release_pending')
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

func (r *PGRepository) ListInOrg(ctx context.Context, orgID string) ([]Hold, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("legalhold: repo not configured")
	}
	if orgID == "" {
		return r.List(ctx)
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, target_user_id, case_ref, reason, created_by,
		    created_at, approved_at, approved_by,
		    released_at, released_by, status, is_active
		 FROM legal_holds
		 WHERE org_id = $1
		 ORDER BY
		    CASE status
		        WHEN 'active' THEN 0
		        WHEN 'pending' THEN 1
		        ELSE 2
		    END,
		    created_at DESC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("legalhold: list scoped: %w", err)
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
		h.OrgID = orgID
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

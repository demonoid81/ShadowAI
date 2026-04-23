//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// Compiled only under -tags enterprise.
//
// Package adminaudit реализует отдельный audit-trail для admin-read
// операций и control-plane действий (PR-D).
//
// Контракт:
//   - НЕ пишет сюда обычные user LLM-запросы (они в audit_logs).
//   - НЕ включает raw bodies, SQL-query text, secrets, DSN.
//   - MetadataJSON — masked/summary (filters, counters, mode=cli|scheduler).
package adminaudit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shadowai/backend/internal/chain"
	"github.com/shadowai/backend/internal/domain"
)

// PurgeTarget — значение для audit_purge_runs.target при purge
// admin_event_logs. Используется CLI и scheduler'ом.
const PurgeTarget = "admin_event_logs"

// PurgeOlderThan удаляет admin_event_logs-rows с created_at < cutoff
// в чанках (защита от lock'ов). Аналогично audit.Repository.PurgeOlderThan,
// но для admin-events-таблицы.
func (r *Repository) PurgeOlderThan(ctx context.Context, cutoff time.Time, chunkSize int) (int, error) {
	if chunkSize <= 0 {
		return 0, fmt.Errorf("admin purge: chunkSize must be > 0, got %d", chunkSize)
	}
	total := 0
	for {
		res, err := r.db.ExecContext(ctx,
			`DELETE FROM admin_event_logs WHERE id IN (
				SELECT id FROM admin_event_logs WHERE created_at < $1 LIMIT $2
			)`, cutoff, chunkSize)
		if err != nil {
			return total, fmt.Errorf("admin purge exec: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("admin purge RowsAffected: %w", err)
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

type Repository struct {
	db          *sql.DB
	chainSecret []byte
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) WithChainSecret(secret string) *Repository {
	c := *r
	c.chainSecret = []byte(secret)
	return &c
}

// Insert сохраняет admin-event. Sync — admin actions редкие, lat.
// оправдана простотой (без async-worker'а и drop-counter'ов).
// PR-W2: при chainSecret != "" пишет seq_no + row_hash.
func (r *Repository) Insert(ctx context.Context, e *domain.AdminEvent) error {
	var actor any
	if e.ActorUserID != nil && *e.ActorUserID != "" {
		actor = *e.ActorUserID
	}
	var meta any
	if e.MetadataJSON != "" {
		meta = e.MetadataJSON
	}
	var target any
	if e.TargetID != "" {
		target = e.TargetID
	}

	if len(r.chainSecret) > 0 {
		return r.insertWithChain(ctx, e, actor, target, meta)
	}

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO admin_event_logs
		 (actor_user_id, action, resource, target_id, path, method, status_code, success, metadata_json)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		actor, e.Action, e.Resource, target, e.Path, e.Method, e.StatusCode, e.Success, meta)
	if err != nil {
		return fmt.Errorf("adminaudit insert: %w", err)
	}
	return nil
}

func (r *Repository) insertWithChain(ctx context.Context, e *domain.AdminEvent, actor, target, meta any) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("adminaudit chain: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// W2 fix: DB генерирует id и created_at по DEFAULT. Чтобы canonical
	// совпал с тем, что хранится в row, генерируем оба в Go и пишем
	// явно в INSERT.
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	createdAt := time.Now().UTC()
	e.CreatedAt = createdAt

	actorStr := ""
	if e.ActorUserID != nil {
		actorStr = *e.ActorUserID
	}
	canonical := chain.CanonicalAdminEventLog(
		e.ID, actorStr, e.Action, e.Resource, e.TargetID,
		e.Path, e.Method, e.StatusCode, e.Success,
		createdAt.Unix(),
	)
	seqNo, rowHash, err := chain.AcquireSlot(ctx, tx,
		chain.TableAdminEventLogs, "admin_event_logs", chain.SeqAdminEventLogs,
		canonical, r.chainSecret)
	if err != nil {
		return fmt.Errorf("adminaudit chain: acquire slot: %w", err)
	}

	var seqArg any
	var hashArg any
	if seqNo > 0 {
		seqArg = seqNo
		hashArg = rowHash
	}

	// INSERT с явными id и created_at ($12, $13) — совпадают с canonical.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO admin_event_logs
		 (actor_user_id, action, resource, target_id, path, method, status_code, success, metadata_json, seq_no, row_hash, id, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		actor, e.Action, e.Resource, target, e.Path, e.Method, e.StatusCode, e.Success, meta,
		seqArg, hashArg, e.ID, createdAt); err != nil {
		return fmt.Errorf("adminaudit chain: insert: %w", err)
	}
	return tx.Commit()
}

// List возвращает страницу admin-event'ов с фильтрами. actorID/resource/
// action = "" → no-op фильтр.
func (r *Repository) List(ctx context.Context, limit, offset int, actorID, resource, action string) ([]domain.AdminEvent, int, error) {
	where := []string{"1=1"}
	args := []any{}
	argIdx := 1
	if actorID != "" {
		where = append(where, fmt.Sprintf("actor_user_id = $%d", argIdx))
		args = append(args, actorID)
		argIdx++
	}
	if resource != "" {
		where = append(where, fmt.Sprintf("resource = $%d", argIdx))
		args = append(args, resource)
		argIdx++
	}
	if action != "" {
		where = append(where, fmt.Sprintf("action = $%d", argIdx))
		args = append(args, action)
		argIdx++
	}
	whereClause := strings.Join(where, " AND ")

	var total int
	_ = r.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT COUNT(*) FROM admin_event_logs WHERE %s`, whereClause),
		args...).Scan(&total)

	query := fmt.Sprintf(`SELECT id, actor_user_id, action, resource, target_id, path, method,
		status_code, success, metadata_json, created_at
		FROM admin_event_logs WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		whereClause, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("adminaudit list: %w", err)
	}
	defer rows.Close()

	var events []domain.AdminEvent
	for rows.Next() {
		var e domain.AdminEvent
		var (
			actor    sql.NullString
			target   sql.NullString
			metaJSON sql.NullString
		)
		if err := rows.Scan(&e.ID, &actor, &e.Action, &e.Resource, &target, &e.Path, &e.Method,
			&e.StatusCode, &e.Success, &metaJSON, &e.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("adminaudit scan: %w", err)
		}
		if actor.Valid {
			a := actor.String
			e.ActorUserID = &a
		}
		if target.Valid {
			e.TargetID = target.String
		}
		if metaJSON.Valid {
			e.MetadataJSON = metaJSON.String
		}
		events = append(events, e)
	}
	return events, total, nil
}

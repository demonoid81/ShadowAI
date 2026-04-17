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

	"github.com/shadowai/backend/internal/domain"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// Insert сохраняет admin-event. Sync — admin actions редкие, lat.
// оправдана простотой (без async-worker'а и drop-counter'ов).
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

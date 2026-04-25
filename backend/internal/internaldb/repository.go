package internaldb

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/lib/pq"
)

type InternalDBSource struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DSN         string    `json:"dsn"`
	Description string    `json:"description"`
	IsActive    bool      `json:"is_active"`
	OrgID       string    `json:"org_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) ListSources(ctx context.Context, orgID string, includeInactive bool) ([]InternalDBSource, error) {
	if r == nil || r.db == nil {
		return []InternalDBSource{}, nil
	}

	var args []any
	argIdx := 1
	conds := "1=1"
	if orgID != "" {
		conds += " AND org_id = $1"
		args = append(args, orgID)
		argIdx++
	}
	_ = argIdx
	if !includeInactive {
		conds += " AND is_active = true"
	}
	query := `SELECT id, name, dsn, COALESCE(description, ''), is_active, created_at, updated_at, COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001')
		FROM internal_db_sources WHERE ` + conds + ` ORDER BY lower(name) ASC`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		if isRelationMissing(err) {
			return []InternalDBSource{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	var out []InternalDBSource
	for rows.Next() {
		var s InternalDBSource
		if err := rows.Scan(&s.ID, &s.Name, &s.DSN, &s.Description, &s.IsActive, &s.CreatedAt, &s.UpdatedAt, &s.OrgID); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func (r *Repository) GetByID(ctx context.Context, id string) (*InternalDBSource, error) {
	if r == nil || r.db == nil {
		return nil, sql.ErrNoRows
	}

	var s InternalDBSource
	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, dsn, COALESCE(description, ''), is_active, created_at, updated_at, COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001')
		FROM internal_db_sources
		WHERE id = $1
	`, id).Scan(&s.ID, &s.Name, &s.DSN, &s.Description, &s.IsActive, &s.CreatedAt, &s.UpdatedAt, &s.OrgID)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// GetByIDScoped looks up an internal DB source by id within the given org.
func (r *Repository) GetByIDScoped(ctx context.Context, id, orgID string) (*InternalDBSource, error) {
	if r == nil || r.db == nil {
		return nil, sql.ErrNoRows
	}
	var s InternalDBSource
	var q string
	var args []any
	if orgID != "" {
		q = `SELECT id, name, dsn, COALESCE(description, ''), is_active, created_at, updated_at, COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001')
		     FROM internal_db_sources WHERE id = $1 AND org_id = $2`
		args = []any{id, orgID}
	} else {
		q = `SELECT id, name, dsn, COALESCE(description, ''), is_active, created_at, updated_at, COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001')
		     FROM internal_db_sources WHERE id = $1`
		args = []any{id}
	}
	err := r.db.QueryRowContext(ctx, q, args...).Scan(
		&s.ID, &s.Name, &s.DSN, &s.Description, &s.IsActive, &s.CreatedAt, &s.UpdatedAt, &s.OrgID)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *Repository) GetByName(ctx context.Context, name string) (*InternalDBSource, error) {
	if r == nil || r.db == nil {
		return nil, sql.ErrNoRows
	}

	var s InternalDBSource
	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, dsn, COALESCE(description, ''), is_active, created_at, updated_at, COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001')
		FROM internal_db_sources
		WHERE lower(name) = lower($1)
	`, name).Scan(&s.ID, &s.Name, &s.DSN, &s.Description, &s.IsActive, &s.CreatedAt, &s.UpdatedAt, &s.OrgID)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *Repository) Create(ctx context.Context, source *InternalDBSource, userID, orgID string) error {
	if r == nil || r.db == nil {
		return errors.New("repository unavailable")
	}
	if source == nil {
		return errors.New("internal db source is required")
	}
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO internal_db_sources (id, name, dsn, description, is_active, created_by, updated_by, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $6, $7)`,
		source.ID, source.Name, source.DSN, source.Description, source.IsActive, toNullableID(userID), orgID)
	return err
}

// UpdateScoped updates a source with org ownership check.
func (r *Repository) UpdateScoped(ctx context.Context, source *InternalDBSource, userID, orgID string) error {
	if r == nil || r.db == nil {
		return errors.New("repository unavailable")
	}
	if source == nil {
		return errors.New("internal db source is required")
	}
	var res sql.Result
	var err error
	if orgID != "" {
		res, err = r.db.ExecContext(ctx,
			`UPDATE internal_db_sources SET name=$1, dsn=$2, description=$3, is_active=$4, updated_by=$5, updated_at=now()
			 WHERE id=$6 AND org_id=$7`,
			source.Name, source.DSN, source.Description, source.IsActive, toNullableID(userID), source.ID, orgID)
	} else {
		res, err = r.db.ExecContext(ctx,
			`UPDATE internal_db_sources SET name=$1, dsn=$2, description=$3, is_active=$4, updated_by=$5, updated_at=now()
			 WHERE id=$6`,
			source.Name, source.DSN, source.Description, source.IsActive, toNullableID(userID), source.ID)
	}
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return ErrSourceNotFound
	}
	return nil
}

// DeleteScoped deletes a source with org ownership check.
func (r *Repository) DeleteScoped(ctx context.Context, id, orgID string) error {
	if r == nil || r.db == nil {
		return sql.ErrNoRows
	}
	var res sql.Result
	var err error
	if orgID != "" {
		res, err = r.db.ExecContext(ctx, `DELETE FROM internal_db_sources WHERE id = $1 AND org_id = $2`, id, orgID)
	} else {
		res, err = r.db.ExecContext(ctx, `DELETE FROM internal_db_sources WHERE id = $1`, id)
	}
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return ErrSourceNotFound
	}
	return nil
}

func (r *Repository) Update(ctx context.Context, source *InternalDBSource, userID string) error {
	if r == nil || r.db == nil {
		return errors.New("repository unavailable")
	}
	if source == nil {
		return errors.New("internal db source is required")
	}

	res, err := r.db.ExecContext(ctx,
		`UPDATE internal_db_sources
		 SET name=$1, dsn=$2, description=$3, is_active=$4, updated_by=$5, updated_at=now()
		 WHERE id=$6`,
		source.Name, source.DSN, source.Description, source.IsActive, toNullableID(userID), source.ID)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrSourceNotFound
	}

	return nil
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	if r == nil || r.db == nil {
		return sql.ErrNoRows
	}

	res, err := r.db.ExecContext(ctx, `DELETE FROM internal_db_sources WHERE id = $1`, id)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrSourceNotFound
	}

	return nil
}

func isRelationMissing(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "42P01"
	}
	return false
}

func toNullableID(value string) interface{} {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

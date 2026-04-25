package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/shadowai/backend/internal/chain"
	"github.com/shadowai/backend/internal/domain"
)

// ScrubUserDataTx обезличивает audit-строки конкретного user'а
// (PR-B): user_id → NULL, request/response bodies → NULL,
// shadow_decisions_json → NULL, pii_types → NULL.
//
// Остальные колонки (status_code, tokens, cost, policy_action,
// created_at) сохраняются: это агрегируемая операционная аналитика
// без привязки к человеку.
//
// Принимает *sql.Tx — чтобы scrub + DELETE user были в одной
// транзакции (atomicity для erasure-workflow).
func (r *Repository) ScrubUserDataTx(ctx context.Context, tx *sql.Tx, userID string) (int, error) {
	res, err := tx.ExecContext(ctx,
		`UPDATE audit_logs
		 SET user_id = NULL,
		     request_body = NULL,
		     response_body = NULL,
		     shadow_decisions_json = NULL,
		     pii_types = NULL
		 WHERE user_id = $1`, userID)
	if err != nil {
		return 0, fmt.Errorf("scrub user data: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("scrub user data RowsAffected: %w", err)
	}
	return int(n), nil
}

type Repository struct {
	db          *sql.DB
	chainSecret []byte // nil/empty = chain disabled
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// WithChainSecret returns a Repository copy configured with the chain secret.
// When non-empty, Insert will write seq_no + row_hash atomically.
func (r *Repository) WithChainSecret(secret string) *Repository {
	c := *r
	c.chainSecret = []byte(secret)
	return &c
}

func (r *Repository) Insert(ctx context.Context, log *domain.AuditLog) error {
	var shadowJSON any
	if log.ShadowDecisionsJSON != "" {
		shadowJSON = log.ShadowDecisionsJSON
	}

	// PR-W2: chain write path. When chainSecret is set, we open a tx,
	// acquire advisory lock, compute seq_no + row_hash, then insert.
	if len(r.chainSecret) > 0 {
		return r.insertWithChain(ctx, log, shadowJSON)
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO audit_logs (id, user_id, request_body, response_body, model, provider, endpoint, status_code, prompt_tokens, completion_tokens, total_tokens, cost_usd, pii_detected, pii_types, policy_action, shadow_decisions_json, duration_ms, outcome, fallback_reason, usage_source)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
		log.ID, log.UserID, log.RequestBody, log.ResponseBody, log.Model, log.Provider, log.Endpoint,
		log.StatusCode, log.PromptTokens, log.CompletionTokens, log.TotalTokens, log.CostUSD,
		log.PIIDetected, pq.Array(log.PIITypes), log.PolicyAction, shadowJSON, log.DurationMs,
		log.Outcome, log.FallbackReason, log.UsageSource)
	return err
}

func (r *Repository) insertWithChain(ctx context.Context, log *domain.AuditLog, shadowJSON any) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit chain: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// W2 fix: capture created_at in Go so canonical и DB INSERT используют
	// одно и то же значение. Без этого canonical хэш не совпадёт с тем,
	// что вернул бы verifier — DB DEFAULT now() ≠ log.CreatedAt (нулевое
	// или уже заполненное handler'ом). Источник истины — это значение.
	createdAt := log.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	} else {
		createdAt = createdAt.UTC()
	}
	log.CreatedAt = createdAt // присваиваем обратно для caller'а

	canonical := chain.CanonicalAuditLog(
		log.ID, log.UserID, log.Model, log.Provider, log.Endpoint,
		log.StatusCode, log.PromptTokens, log.CompletionTokens, log.TotalTokens,
		chain.CostMicrocents(log.CostUSD),
		log.PIIDetected, log.PIITypes,
		log.PolicyAction, log.Outcome, log.FallbackReason, log.UsageSource,
		createdAt.Unix(),
	)

	seqNo, rowHash, err := chain.AcquireSlot(ctx, tx,
		chain.TableAuditLogs, "audit_logs", chain.SeqAuditLogs,
		canonical, r.chainSecret)
	if err != nil {
		return fmt.Errorf("audit chain: acquire slot: %w", err)
	}

	var seqArg any
	var hashArg any
	if seqNo > 0 {
		seqArg = seqNo
		hashArg = rowHash
	}

	// INSERT с явным created_at ($23) — не полагаемся на DB DEFAULT.
	// Это гарантирует совпадение с canonical.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_logs (id, user_id, request_body, response_body, model, provider, endpoint, status_code, prompt_tokens, completion_tokens, total_tokens, cost_usd, pii_detected, pii_types, policy_action, shadow_decisions_json, duration_ms, outcome, fallback_reason, usage_source, seq_no, row_hash, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
		log.ID, log.UserID, log.RequestBody, log.ResponseBody, log.Model, log.Provider, log.Endpoint,
		log.StatusCode, log.PromptTokens, log.CompletionTokens, log.TotalTokens, log.CostUSD,
		log.PIIDetected, pq.Array(log.PIITypes), log.PolicyAction, shadowJSON, log.DurationMs,
		log.Outcome, log.FallbackReason, log.UsageSource,
		seqArg, hashArg, createdAt); err != nil {
		return fmt.Errorf("audit chain: insert: %w", err)
	}

	return tx.Commit()
}

// recordPurgeRunChained пишет ОДНУ chained row в audit_purge_runs
// с фактическим rowsDeleted. Вызывается внутри существующей purge tx
// ПОСЛЕ DELETE — содержит реальное количество удалённых rows.
//
// W2.1 fix: заменяет отдельный pre-purge anchor (который создавал
// два rows на одну операцию с rows_deleted=0, ломая LastPurgeRun).
//
// Если chainSecret пустой — пишет обычный INSERT без chain fields.
func (r *Repository) recordPurgeRunChained(ctx context.Context, tx *sql.Tx, cutoff time.Time, rowsDeleted int, target string) error {
	runID := uuid.New().String()
	completedAt := time.Now().UTC()

	if len(r.chainSecret) == 0 {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO audit_purge_runs (id, cutoff, rows_deleted, completed_at, target)
			 VALUES ($1, $2, $3, $4, $5)`,
			runID, cutoff, rowsDeleted, completedAt, target)
		return err
	}

	canonical := chain.CanonicalAuditPurgeRun(runID, cutoff.Unix(), rowsDeleted, target, completedAt.Unix())
	seqNo, rowHash, err := chain.AcquireSlot(ctx, tx,
		chain.TableAuditPurgeRuns, "audit_purge_runs", chain.SeqAuditPurgeRuns,
		canonical, r.chainSecret)
	if err != nil {
		return fmt.Errorf("purge run chain: acquire slot: %w", err)
	}
	var seqArg any
	var hashArg any
	if seqNo > 0 {
		seqArg = seqNo
		hashArg = rowHash
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO audit_purge_runs (id, cutoff, rows_deleted, completed_at, target, seq_no, row_hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		runID, cutoff, rowsDeleted, completedAt, target, seqArg, hashArg)
	return err
}


func (r *Repository) List(ctx context.Context, limit, offset int, orgID, userID, model, policyAction, hasShadow string) ([]domain.AuditLog, int, error) {
	where := []string{"1=1"}
	args := []any{}
	argIdx := 1

	if orgID != "" {
		where = append(where, fmt.Sprintf("org_id = $%d", argIdx))
		args = append(args, orgID)
		argIdx++
	}
	if userID != "" {
		where = append(where, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, userID)
		argIdx++
	}
	if model != "" {
		where = append(where, fmt.Sprintf("model = $%d", argIdx))
		args = append(args, model)
		argIdx++
	}
	if policyAction != "" {
		where = append(where, fmt.Sprintf("policy_action = $%d", argIdx))
		args = append(args, policyAction)
		argIdx++
	}
	// PR-4.1: has_shadow filter. Значения валидируются в handler,
	// здесь trust'им. "" и "any" — no-op.
	switch hasShadow {
	case "yes":
		where = append(where, "shadow_decisions_json IS NOT NULL")
	case "no":
		where = append(where, "shadow_decisions_json IS NULL")
	}

	whereClause := strings.Join(where, " AND ")

	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_logs WHERE %s", whereClause)
	r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)

	// PR-F7.3: SELECT расширен на outcome/fallback_reason/usage_source.
	// Миграция 009 гарантирует NOT NULL DEFAULT '' для них, так что
	// sql.NullString wrapping не нужен — поля всегда возвращают
	// string (возможно пустую).
	query := fmt.Sprintf(`SELECT id, user_id, request_body, response_body, model, provider, endpoint, status_code,
		prompt_tokens, completion_tokens, total_tokens, cost_usd, pii_detected, pii_types, policy_action, shadow_decisions_json, duration_ms, outcome, fallback_reason, usage_source, created_at
		FROM audit_logs WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, whereClause, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []domain.AuditLog
	for rows.Next() {
		var l domain.AuditLog
		// PR-B: после erasure user_id, request_body, response_body,
		// shadow_decisions_json могут быть NULL. Сканируем через
		// sql.NullString и преобразуем в пустую string (domain-тип
		// не меняем, чтобы не ломать downstream JSON-shape).
		var (
			userID      sql.NullString
			requestBody sql.NullString
			respBody    sql.NullString
			shadowJSON  sql.NullString
		)
		if err := rows.Scan(&l.ID, &userID, &requestBody, &respBody, &l.Model, &l.Provider, &l.Endpoint,
			&l.StatusCode, &l.PromptTokens, &l.CompletionTokens, &l.TotalTokens, &l.CostUSD,
			&l.PIIDetected, pq.Array(&l.PIITypes), &l.PolicyAction, &shadowJSON, &l.DurationMs,
			&l.Outcome, &l.FallbackReason, &l.UsageSource, &l.CreatedAt); err != nil {
			return nil, 0, err
		}
		if userID.Valid {
			l.UserID = userID.String
		}
		if requestBody.Valid {
			l.RequestBody = requestBody.String
		}
		if respBody.Valid {
			l.ResponseBody = respBody.String
		}
		if shadowJSON.Valid {
			l.ShadowDecisionsJSON = shadowJSON.String
		}
		logs = append(logs, l)
	}
	return logs, total, nil
}

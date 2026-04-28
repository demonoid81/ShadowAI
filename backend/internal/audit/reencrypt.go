package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/shadowai/backend/internal/byok"
	"github.com/shadowai/backend/internal/domain"
)

type ReencryptOptions struct {
	Limit  int
	OrgID  string
	DryRun bool
}

type ReencryptResult struct {
	Scanned                 int
	WouldUpdate             int
	Updated                 int
	SkippedConcurrentUpdate int
	RequestFieldsEncrypted  int
	ResponseFieldsEncrypted int
}

type auditPayloadSweepRow struct {
	ID           string
	OrgID        string
	RequestBody  string
	ResponseBody string
}

func (r *Repository) ReencryptLegacyPayloads(ctx context.Context, opts ReencryptOptions) (ReencryptResult, error) {
	if opts.Limit <= 0 {
		return ReencryptResult{}, fmt.Errorf("limit must be > 0")
	}
	if !opts.DryRun && r.payloadEncryptor == nil {
		return ReencryptResult{}, fmt.Errorf("BYOK encryptor is required unless dry-run is true")
	}
	rows, err := r.fetchPayloadSweepRows(ctx, opts)
	if err != nil {
		return ReencryptResult{}, err
	}
	var result ReencryptResult
	result.Scanned = len(rows)
	for _, row := range rows {
		changedReq := needsPayloadEncryption(row.RequestBody)
		changedResp := needsPayloadEncryption(row.ResponseBody)
		if !changedReq && !changedResp {
			continue
		}
		result.WouldUpdate++
		if changedReq {
			result.RequestFieldsEncrypted++
		}
		if changedResp {
			result.ResponseFieldsEncrypted++
		}
		if opts.DryRun {
			continue
		}
		next, _, _, err := reencryptPayloadValues(ctx, r.payloadEncryptor, row.OrgID, row)
		if err != nil {
			return result, err
		}
		updated, err := r.updatePayloadSweepRow(ctx, row, next, changedReq, changedResp)
		if err != nil {
			return result, err
		}
		if updated {
			result.Updated++
		} else {
			result.SkippedConcurrentUpdate++
		}
	}
	return result, nil
}

func (r *Repository) fetchPayloadSweepRows(ctx context.Context, opts ReencryptOptions) ([]auditPayloadSweepRow, error) {
	args := []any{}
	where := []string{"(COALESCE(request_body, '') <> '' OR COALESCE(response_body, '') <> '')"}
	if strings.TrimSpace(opts.OrgID) != "" {
		args = append(args, strings.TrimSpace(opts.OrgID))
		where = append(where, fmt.Sprintf("org_id = $%d", len(args)))
	}
	args = append(args, opts.Limit)
	query := fmt.Sprintf(`SELECT id,
		COALESCE(org_id::text, $%d),
		COALESCE(request_body, ''),
		COALESCE(response_body, '')
		FROM audit_logs
		WHERE %s
		ORDER BY created_at ASC, id ASC
		LIMIT $%d`, len(args)+1, strings.Join(where, " AND "), len(args))
	args = append(args, domain.DefaultOrgID)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("fetch BYOK sweep rows: %w", err)
	}
	defer rows.Close()

	var out []auditPayloadSweepRow
	for rows.Next() {
		var row auditPayloadSweepRow
		if err := rows.Scan(&row.ID, &row.OrgID, &row.RequestBody, &row.ResponseBody); err != nil {
			return nil, fmt.Errorf("scan BYOK sweep row: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate BYOK sweep rows: %w", err)
	}
	return out, nil
}

func (r *Repository) updatePayloadSweepRow(ctx context.Context, oldRow, next auditPayloadSweepRow, changedReq, changedResp bool) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE audit_logs
		SET request_body = CASE WHEN $2 THEN $3 ELSE request_body END,
		    response_body = CASE WHEN $4 THEN $5 ELSE response_body END
		WHERE id = $1
		  AND COALESCE(request_body, '') = $6
		  AND COALESCE(response_body, '') = $7`,
		oldRow.ID,
		changedReq, sql.NullString{String: next.RequestBody, Valid: true},
		changedResp, sql.NullString{String: next.ResponseBody, Valid: true},
		oldRow.RequestBody, oldRow.ResponseBody)
	if err != nil {
		return false, fmt.Errorf("update BYOK sweep row %s: %w", oldRow.ID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("update BYOK sweep row %s RowsAffected: %w", oldRow.ID, err)
	}
	return n == 1, nil
}

func reencryptPayloadValues(ctx context.Context, enc byok.Encryptor, orgID string, row auditPayloadSweepRow) (auditPayloadSweepRow, bool, bool, error) {
	next := row
	changedReq := needsPayloadEncryption(row.RequestBody)
	changedResp := needsPayloadEncryption(row.ResponseBody)
	var err error
	if changedReq {
		next.RequestBody, err = byok.EncryptString(ctx, enc, orgID, "request_body", row.RequestBody)
		if err != nil {
			return auditPayloadSweepRow{}, false, false, fmt.Errorf("BYOK sweep encrypt request_body for row %s: %w", row.ID, err)
		}
	}
	if changedResp {
		next.ResponseBody, err = byok.EncryptString(ctx, enc, orgID, "response_body", row.ResponseBody)
		if err != nil {
			return auditPayloadSweepRow{}, false, false, fmt.Errorf("BYOK sweep encrypt response_body for row %s: %w", row.ID, err)
		}
	}
	return next, changedReq, changedResp, nil
}

func needsPayloadEncryption(value string) bool {
	if value == "" {
		return false
	}
	if !byok.IsEnvelopeString(value) {
		return true
	}
	_, err := byok.DecodeEnvelope(value)
	return err != nil
}

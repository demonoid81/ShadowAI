package evidencebundle

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lib/pq"
	"github.com/shadowai/backend/internal/legalholdselector"
)

const SelectorManifestFilename = "selector_manifest.jsonl"

// SelectorManifestLine is one query_scope legal hold selector exported into an
// evidence bundle. The selector JSON is the normalized selector stored in
// legal_holds.scope_query_json; SelectorHash is SHA256(normalized selector JSON).
type SelectorManifestLine struct {
	HoldID          string          `json:"hold_id"`
	OrgID           string          `json:"org_id,omitempty"`
	ScopeType       string          `json:"scope_type"`
	SelectorHash    string          `json:"selector_hash"`
	SelectorVersion int             `json:"selector_version"`
	SelectorJSON    json.RawMessage `json:"selector_json"`
}

// SelectorManifestResult covers offline selector hash verification.
type SelectorManifestResult struct {
	OK      bool
	Missing bool // true for legacy bundles that predate selector_manifest.jsonl
	Checked int
	Fails   []SelectorManifestFail
}

// SelectorManifestFail describes one selector line that failed verification.
type SelectorManifestFail struct {
	HoldID string
	OrgID  string
	Reason string
}

// SelectorManifestRepository fetches query_scope legal hold selectors for
// evidence bundle export.
type SelectorManifestRepository struct {
	db *sql.DB
}

func NewSelectorManifestRepository(db *sql.DB) *SelectorManifestRepository {
	return &SelectorManifestRepository{db: db}
}

// Fetch returns query_scope selector manifest lines.
//
// orgID empty → global export (all query_scope selectors).
// orgID non-empty → tenant export (only legal_holds.org_id = orgID).
func (r *SelectorManifestRepository) Fetch(ctx context.Context, orgID string) ([]SelectorManifestLine, error) {
	query := `SELECT id::text,
	                 COALESCE(org_id::text, ''),
	                 scope_type,
	                 scope_query_hash,
	                 COALESCE(scope_query_version, 1),
	                 scope_query_json::text
	          FROM legal_holds
	          WHERE scope_type = 'query_scope'
	            AND scope_query_json IS NOT NULL
	            AND scope_query_hash IS NOT NULL`
	var args []any
	if strings.TrimSpace(orgID) != "" {
		query += ` AND org_id = $1`
		args = append(args, strings.TrimSpace(orgID))
	}
	query += ` ORDER BY created_at, id`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		if isOptionalSelectorManifestTableError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("selector manifest: query legal_holds: %w", err)
	}
	defer rows.Close()

	var result []SelectorManifestLine
	for rows.Next() {
		var line SelectorManifestLine
		var version int64
		var selectorJSON string
		if err := rows.Scan(
			&line.HoldID,
			&line.OrgID,
			&line.ScopeType,
			&line.SelectorHash,
			&version,
			&selectorJSON,
		); err != nil {
			return nil, fmt.Errorf("selector manifest: scan legal_holds: %w", err)
		}
		line.SelectorVersion = int(version)
		line.SelectorJSON = json.RawMessage(selectorJSON)
		result = append(result, line)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("selector manifest: rows: %w", err)
	}
	return result, nil
}

func isOptionalSelectorManifestTableError(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && string(pqErr.Code) == "42P01" // undefined_table: core DB has no legal_holds
}

func checkSelectorManifest(dir string) SelectorManifestResult {
	res := SelectorManifestResult{OK: true}
	lines, err := readSelectorManifestNDJSON(filepath.Join(dir, SelectorManifestFilename))
	if err != nil {
		if os.IsNotExist(err) {
			res.Missing = true
			return res
		}
		res.OK = false
		res.Fails = append(res.Fails, SelectorManifestFail{Reason: err.Error()})
		return res
	}
	for _, line := range lines {
		res.Checked++
		if reason := verifySelectorManifestLine(line); reason != "" {
			res.OK = false
			res.Fails = append(res.Fails, SelectorManifestFail{
				HoldID: line.HoldID,
				OrgID:  line.OrgID,
				Reason: reason,
			})
		}
	}
	return res
}

func verifySelectorManifestLine(line SelectorManifestLine) string {
	if line.HoldID == "" {
		return "hold_id is empty"
	}
	if line.ScopeType != "query_scope" {
		return fmt.Sprintf("scope_type = %q, want query_scope", line.ScopeType)
	}
	if line.SelectorVersion != 1 {
		return fmt.Sprintf("selector_version = %d, want 1", line.SelectorVersion)
	}
	if len(line.SelectorJSON) == 0 {
		return "selector_json is empty"
	}
	compiled, err := legalholdselector.Compile(line.SelectorJSON, legalholdselector.CompileOptions{})
	if err != nil {
		return fmt.Sprintf("selector_json invalid: %v", err)
	}
	if compiled.Hash != line.SelectorHash {
		return fmt.Sprintf("selector_hash mismatch: computed=%s stored=%s", compiled.Hash, line.SelectorHash)
	}
	return ""
}

func readSelectorManifestNDJSON(path string) ([]SelectorManifestLine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var result []SelectorManifestLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var selector SelectorManifestLine
		if err := json.Unmarshal([]byte(line), &selector); err != nil {
			return nil, fmt.Errorf("%s: parse: %w", SelectorManifestFilename, err)
		}
		result = append(result, selector)
	}
	return result, sc.Err()
}

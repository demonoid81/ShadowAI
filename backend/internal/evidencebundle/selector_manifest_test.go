package evidencebundle

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/lib/pq"
	"github.com/shadowai/backend/internal/legalholdselector"
)

type selectorManifestMockDriver struct {
	mu   sync.Mutex
	rows []selectorManifestMockRow
}

type selectorManifestMockRow struct {
	holdID          string
	orgID           string
	scopeType       string
	selectorHash    string
	selectorVersion int64
	selectorJSON    string
}

var (
	selectorManifestDriverOnce sync.Once
	selectorManifestDriver     = &selectorManifestMockDriver{}
)

func init() {
	selectorManifestDriverOnce.Do(func() {
		sql.Register("mock_selector_manifest", selectorManifestDriver)
	})
}

func (d *selectorManifestMockDriver) setRows(rows []selectorManifestMockRow) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rows = rows
}

func (d *selectorManifestMockDriver) Open(_ string) (driver.Conn, error) {
	d.mu.Lock()
	rows := make([]selectorManifestMockRow, len(d.rows))
	copy(rows, d.rows)
	d.mu.Unlock()
	return &selectorManifestMockConn{rows: rows}, nil
}

type selectorManifestMockConn struct {
	rows []selectorManifestMockRow
}

func (c *selectorManifestMockConn) Prepare(_ string) (driver.Stmt, error) {
	return &selectorManifestMockStmt{rows: c.rows}, nil
}
func (c *selectorManifestMockConn) Close() error { return nil }
func (c *selectorManifestMockConn) Begin() (driver.Tx, error) {
	return nil, fmt.Errorf("transactions not supported")
}

type selectorManifestMockStmt struct {
	rows []selectorManifestMockRow
}

func (s *selectorManifestMockStmt) Close() error  { return nil }
func (s *selectorManifestMockStmt) NumInput() int { return -1 }
func (s *selectorManifestMockStmt) Exec(_ []driver.Value) (driver.Result, error) {
	return nil, fmt.Errorf("exec not supported")
}
func (s *selectorManifestMockStmt) Query(args []driver.Value) (driver.Rows, error) {
	orgFilter := ""
	if len(args) > 0 {
		orgFilter = fmt.Sprint(args[0])
	}
	var rows []selectorManifestMockRow
	for _, row := range s.rows {
		if orgFilter != "" && row.orgID != orgFilter {
			continue
		}
		rows = append(rows, row)
	}
	return &selectorManifestMockRows{rows: rows}, nil
}

type selectorManifestMockRows struct {
	rows []selectorManifestMockRow
	pos  int
}

func (r *selectorManifestMockRows) Columns() []string {
	return []string{"hold_id", "org_id", "scope_type", "scope_query_hash", "scope_query_version", "scope_query_json"}
}
func (r *selectorManifestMockRows) Close() error { return nil }
func (r *selectorManifestMockRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.rows) {
		return io.EOF
	}
	row := r.rows[r.pos]
	r.pos++
	dest[0] = row.holdID
	dest[1] = row.orgID
	dest[2] = row.scopeType
	dest[3] = row.selectorHash
	dest[4] = row.selectorVersion
	dest[5] = row.selectorJSON
	return nil
}

func openSelectorManifestMockDB(t *testing.T, rows []selectorManifestMockRow) *sql.DB {
	t.Helper()
	selectorManifestDriver.setRows(rows)
	db, err := sql.Open("mock_selector_manifest", "mock")
	if err != nil {
		t.Fatalf("open mock db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func selectorMockRow(t *testing.T, holdID, orgID, raw string) selectorManifestMockRow {
	t.Helper()
	compiled, err := legalholdselector.Compile(json.RawMessage(raw), legalholdselector.CompileOptions{})
	if err != nil {
		t.Fatalf("compile selector: %v", err)
	}
	return selectorManifestMockRow{
		holdID:          holdID,
		orgID:           orgID,
		scopeType:       "query_scope",
		selectorHash:    compiled.Hash,
		selectorVersion: 1,
		selectorJSON:    string(compiled.NormalizedJSON),
	}
}

func TestFetchSelectorManifest_GlobalIncludesAllQueryScopeSelectors(t *testing.T) {
	db := openSelectorManifestMockDB(t, []selectorManifestMockRow{
		selectorMockRow(t, "hold-a", "org-a", `{"v":1,"field":"provider","op":"eq","value":"openai"}`),
		selectorMockRow(t, "hold-b", "org-b", `{"v":1,"field":"provider","op":"eq","value":"anthropic"}`),
	})

	repo := NewSelectorManifestRepository(db)
	lines, err := repo.Fetch(context.Background(), "")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("global selector manifest rows = %d, want 2", len(lines))
	}
}

func TestFetchSelectorManifest_TenantFiltersByOrg(t *testing.T) {
	db := openSelectorManifestMockDB(t, []selectorManifestMockRow{
		selectorMockRow(t, "hold-a", "org-a", `{"v":1,"field":"provider","op":"eq","value":"openai"}`),
		selectorMockRow(t, "hold-b", "org-b", `{"v":1,"field":"provider","op":"eq","value":"anthropic"}`),
	})

	repo := NewSelectorManifestRepository(db)
	lines, err := repo.Fetch(context.Background(), "org-a")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("tenant selector manifest rows = %d, want 1", len(lines))
	}
	if lines[0].HoldID != "hold-a" || lines[0].OrgID != "org-a" {
		t.Fatalf("unexpected tenant selector row: %+v", lines[0])
	}
}

func TestFetchSelectorManifest_NoQueryScopeRows(t *testing.T) {
	db := openSelectorManifestMockDB(t, nil)
	repo := NewSelectorManifestRepository(db)
	lines, err := repo.Fetch(context.Background(), "org-a")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("selector manifest rows = %d, want 0", len(lines))
	}
}

func TestSelectorManifestUndefinedTableIsOptional(t *testing.T) {
	if !isOptionalSelectorManifestTableError(&pq.Error{Code: "42P01"}) {
		t.Fatal("undefined_table must be optional so core audit_logs export keeps working without enterprise legal_holds")
	}
	if isOptionalSelectorManifestTableError(&pq.Error{Code: "42703"}) {
		t.Fatal("undefined_column must remain fail-hard; it indicates a broken enterprise migration")
	}
}

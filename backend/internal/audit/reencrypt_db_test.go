package audit

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/shadowai/backend/internal/byok"
)

type sweepMockDriver struct {
	mu    sync.Mutex
	rows  []auditPayloadSweepRow
	execs int
}

var (
	sweepDriverOnce sync.Once
	sweepDriver     = &sweepMockDriver{}
)

func init() {
	sweepDriverOnce.Do(func() {
		sql.Register("mock_byok_sweep", sweepDriver)
	})
}

func (d *sweepMockDriver) Open(_ string) (driver.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows := make([]auditPayloadSweepRow, len(d.rows))
	copy(rows, d.rows)
	return &sweepMockConn{driver: d, rows: rows}, nil
}

func (d *sweepMockDriver) setRows(rows []auditPayloadSweepRow) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rows = rows
	d.execs = 0
}

func (d *sweepMockDriver) execCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.execs
}

type sweepMockConn struct {
	driver *sweepMockDriver
	rows   []auditPayloadSweepRow
}

func (c *sweepMockConn) Prepare(query string) (driver.Stmt, error) {
	return nil, fmt.Errorf("Prepare not supported")
}
func (c *sweepMockConn) Close() error { return nil }
func (c *sweepMockConn) Begin() (driver.Tx, error) {
	return nil, fmt.Errorf("transactions not supported")
}

func (c *sweepMockConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	_ = ctx
	_ = query
	_ = args
	return &sweepMockRows{rows: c.rows}, nil
}

func (c *sweepMockConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	_ = ctx
	_ = query
	_ = args
	c.driver.mu.Lock()
	defer c.driver.mu.Unlock()
	c.driver.execs++
	return driver.RowsAffected(1), nil
}

type sweepMockRows struct {
	rows []auditPayloadSweepRow
	pos  int
}

func (r *sweepMockRows) Columns() []string {
	return []string{"id", "org_id", "request_body", "response_body"}
}
func (r *sweepMockRows) Close() error { return nil }
func (r *sweepMockRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.rows) {
		return io.EOF
	}
	row := r.rows[r.pos]
	r.pos++
	dest[0] = row.ID
	dest[1] = row.OrgID
	dest[2] = row.RequestBody
	dest[3] = row.ResponseBody
	return nil
}

func openSweepMockDB(t *testing.T, rows []auditPayloadSweepRow) *sql.DB {
	t.Helper()
	sweepDriver.setRows(rows)
	db, err := sql.Open("mock_byok_sweep", "mock")
	if err != nil {
		t.Fatalf("open mock db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestReencryptLegacyPayloads_DryRunNoKMSNoUpdate(t *testing.T) {
	db := openSweepMockDB(t, []auditPayloadSweepRow{{ID: "row-1", OrgID: "org-a", RequestBody: "legacy"}})
	enc := &stubPayloadEncryptor{}
	repo := NewRepository(db).WithPayloadEncryptor(enc)

	result, err := repo.ReencryptLegacyPayloads(context.Background(), ReencryptOptions{Limit: 10, DryRun: true})
	if err != nil {
		t.Fatalf("ReencryptLegacyPayloads: %v", err)
	}
	if result.Scanned != 1 || result.WouldUpdate != 1 || result.Updated != 0 || result.RequestFieldsEncrypted != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(enc.calls) != 0 {
		t.Fatalf("dry-run must not call KMS encryptor, calls=%v", enc.calls)
	}
	if sweepDriver.execCount() != 0 {
		t.Fatalf("dry-run must not update DB, execs=%d", sweepDriver.execCount())
	}
}

func TestReencryptLegacyPayloads_UpdatesPlaintextOnly(t *testing.T) {
	env, err := byok.EncodeEnvelope(byok.Envelope{V: 1, Alg: byok.AlgVaultTransit, KID: "vault:transit/audit-key", Field: "response_body", CT: "vault:v1:x"})
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	db := openSweepMockDB(t, []auditPayloadSweepRow{
		{ID: "row-1", OrgID: "org-a", RequestBody: "legacy", ResponseBody: env},
		{ID: "row-2", OrgID: "org-a", RequestBody: "", ResponseBody: ""},
	})
	enc := &stubPayloadEncryptor{}
	repo := NewRepository(db).WithPayloadEncryptor(enc)

	result, err := repo.ReencryptLegacyPayloads(context.Background(), ReencryptOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ReencryptLegacyPayloads: %v", err)
	}
	if result.Scanned != 2 || result.WouldUpdate != 1 || result.Updated != 1 || result.RequestFieldsEncrypted != 1 || result.ResponseFieldsEncrypted != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if sweepDriver.execCount() != 1 {
		t.Fatalf("expected one update exec, got %d", sweepDriver.execCount())
	}
}

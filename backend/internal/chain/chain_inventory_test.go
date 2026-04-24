package chain

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Minimal mock SQL driver for FetchChainInventory unit tests.
// Allows injecting specific rows without a real Postgres connection.
// ---------------------------------------------------------------------------

// mockInventoryDriver is a database/sql/driver.Driver returning preset rows.
// Registered once per test package under a unique name.
type mockInventoryDriver struct {
	mu   sync.Mutex
	rows []mockRow
}

type mockRow struct {
	id      string
	seqNo   int64
	rowHash []byte
}

var (
	inventoryDriverOnce sync.Once
	inventoryDriver     = &mockInventoryDriver{}
)

func init() {
	// Register once; each test call setRows before Open.
	inventoryDriverOnce.Do(func() {
		sql.Register("mock_inventory", inventoryDriver)
	})
}

func (d *mockInventoryDriver) setRows(rows []mockRow) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rows = rows
}

func (d *mockInventoryDriver) Open(_ string) (driver.Conn, error) {
	d.mu.Lock()
	rows := make([]mockRow, len(d.rows))
	copy(rows, d.rows)
	d.mu.Unlock()
	return &mockInventoryConn{rows: rows}, nil
}

type mockInventoryConn struct {
	rows []mockRow
}

func (c *mockInventoryConn) Prepare(query string) (driver.Stmt, error) {
	return &mockInventoryStmt{rows: c.rows}, nil
}
func (c *mockInventoryConn) Close() error { return nil }
func (c *mockInventoryConn) Begin() (driver.Tx, error) {
	return nil, fmt.Errorf("transactions not supported in mock")
}

type mockInventoryStmt struct {
	rows []mockRow
}

func (s *mockInventoryStmt) Close() error  { return nil }
func (s *mockInventoryStmt) NumInput() int { return -1 } // variadic
func (s *mockInventoryStmt) Exec(_ []driver.Value) (driver.Result, error) {
	return nil, fmt.Errorf("exec not supported in mock")
}
func (s *mockInventoryStmt) Query(_ []driver.Value) (driver.Rows, error) {
	return &mockInventoryRows{rows: s.rows, pos: 0}, nil
}

type mockInventoryRows struct {
	rows []mockRow
	pos  int
}

func (r *mockInventoryRows) Columns() []string { return []string{"id", "seq_no", "row_hash"} }
func (r *mockInventoryRows) Close() error       { return nil }
func (r *mockInventoryRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.rows) {
		return io.EOF
	}
	row := r.rows[r.pos]
	r.pos++
	dest[0] = row.id
	dest[1] = row.seqNo
	dest[2] = row.rowHash
	return nil
}

// openMockDB returns a *sql.DB backed by the mock driver.
func openMockDB(t *testing.T, rows []mockRow) *sql.DB {
	t.Helper()
	inventoryDriver.setRows(rows)
	db, err := sql.Open("mock_inventory", "mock")
	if err != nil {
		t.Fatalf("open mock db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ---------------------------------------------------------------------------
// FetchChainInventory tests
// ---------------------------------------------------------------------------

// TestFetchChainInventory_EmptyTable returns empty slice with no error.
func TestFetchChainInventory_EmptyTable(t *testing.T) {
	db := openMockDB(t, nil)
	repo := NewAnchorRepository(db)
	result, err := repo.FetchChainInventory(context.Background(), "audit_logs")
	if err != nil {
		t.Fatalf("FetchChainInventory: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d rows", len(result))
	}
}

// TestFetchChainInventory_RowIDHashDerivation verifies RowIDHash = hex(SHA256(rowID)).
func TestFetchChainInventory_RowIDHashDerivation(t *testing.T) {
	rowID := "550e8400-e29b-41d4-a716-446655440000"
	rowHash := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	db := openMockDB(t, []mockRow{
		{id: rowID, seqNo: 1, rowHash: rowHash},
	})
	repo := NewAnchorRepository(db)
	result, err := repo.FetchChainInventory(context.Background(), "audit_logs")
	if err != nil {
		t.Fatalf("FetchChainInventory: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 row, got %d", len(result))
	}

	// Verify RowIDHash = hex(SHA256(rowID)).
	h := sha256.Sum256([]byte(rowID))
	wantIDHash := hex.EncodeToString(h[:])
	if result[0].RowIDHash != wantIDHash {
		t.Errorf("RowIDHash = %q, want %q", result[0].RowIDHash, wantIDHash)
	}

	// Verify RowHashHex = hex(rowHash).
	wantHashHex := hex.EncodeToString(rowHash)
	if result[0].RowHashHex != wantHashHex {
		t.Errorf("RowHashHex = %q, want %q", result[0].RowHashHex, wantHashHex)
	}

	if result[0].SeqNo != 1 {
		t.Errorf("SeqNo = %d, want 1", result[0].SeqNo)
	}
}

// TestFetchChainInventory_MultipleRows verifies ordering and count.
func TestFetchChainInventory_MultipleRows(t *testing.T) {
	rows := []mockRow{
		{id: "id-1", seqNo: 1, rowHash: []byte{0x01}},
		{id: "id-2", seqNo: 2, rowHash: []byte{0x02}},
		{id: "id-3", seqNo: 3, rowHash: []byte{0x03}},
	}
	db := openMockDB(t, rows)
	repo := NewAnchorRepository(db)
	result, err := repo.FetchChainInventory(context.Background(), "audit_logs")
	if err != nil {
		t.Fatalf("FetchChainInventory: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(result))
	}
	for i, r := range result {
		if r.SeqNo != int64(i+1) {
			t.Errorf("row %d: SeqNo = %d, want %d", i, r.SeqNo, i+1)
		}
		// RowIDHash must be 64-char hex string (SHA256 = 32 bytes).
		if len(r.RowIDHash) != 64 {
			t.Errorf("row %d: RowIDHash length = %d, want 64", i, len(r.RowIDHash))
		}
	}
}

// TestFetchChainInventory_RowIDHash_HidesRowID verifies that original row ID
// is not recoverable from RowIDHash (one-way property of SHA256).
func TestFetchChainInventory_RowIDHash_HidesRowID(t *testing.T) {
	rowID := "sensitive-row-uuid-12345"
	db := openMockDB(t, []mockRow{
		{id: rowID, seqNo: 1, rowHash: []byte{0xFF}},
	})
	repo := NewAnchorRepository(db)
	result, _ := repo.FetchChainInventory(context.Background(), "audit_logs")
	if len(result) == 0 {
		t.Fatal("expected 1 result")
	}
	if result[0].RowIDHash == rowID {
		t.Error("RowIDHash must not equal the plain row ID")
	}
	if len(result[0].RowIDHash) != 64 {
		t.Errorf("RowIDHash must be 64-char SHA256 hex, got len=%d", len(result[0].RowIDHash))
	}
}

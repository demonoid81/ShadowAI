package internaldb

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// sanitizeQuery
// ---------------------------------------------------------------------------

func TestSanitizeQuery(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		requestedRows int
		wantQuery     string
		wantLimit     int
		wantErr       error
	}{
		// --- valid queries ---
		{
			name:      "simple SELECT",
			raw:       "SELECT 1",
			wantQuery: "SELECT 1",
			wantLimit: defaultRowsLimit,
		},
		{
			name:      "SELECT with leading/trailing whitespace",
			raw:       "  SELECT id FROM users  ",
			wantQuery: "SELECT id FROM users",
			wantLimit: defaultRowsLimit,
		},
		{
			name:      "WITH (CTE) query",
			raw:       "WITH cte AS (SELECT 1) SELECT * FROM cte",
			wantQuery: "WITH cte AS (SELECT 1) SELECT * FROM cte",
			wantLimit: defaultRowsLimit,
		},
		{
			name:      "case insensitive SELECT",
			raw:       "select id from t",
			wantQuery: "select id from t",
			wantLimit: defaultRowsLimit,
		},
		{
			name:      "case insensitive WITH",
			raw:       "with x as (select 1) select * from x",
			wantQuery: "with x as (select 1) select * from x",
			wantLimit: defaultRowsLimit,
		},
		{
			name:      "trailing semicolon stripped",
			raw:       "SELECT 1;",
			wantQuery: "SELECT 1",
			wantLimit: defaultRowsLimit,
		},
		{
			name:      "trailing semicolon with whitespace after trim",
			raw:       "SELECT 1 ;",
			wantQuery: "SELECT 1",
			wantLimit: defaultRowsLimit,
		},

		// --- row limits ---
		{
			name:          "custom rows within range",
			raw:           "SELECT 1",
			requestedRows: 50,
			wantQuery:     "SELECT 1",
			wantLimit:     50,
		},
		{
			name:          "rows clamped to max",
			raw:           "SELECT 1",
			requestedRows: 5000,
			wantQuery:     "SELECT 1",
			wantLimit:     maxRowsLimit,
		},
		{
			name:          "rows = 1 (minimum)",
			raw:           "SELECT 1",
			requestedRows: 1,
			wantQuery:     "SELECT 1",
			wantLimit:     1,
		},
		{
			name:          "rows = 0 falls back to default",
			raw:           "SELECT 1",
			requestedRows: 0,
			wantQuery:     "SELECT 1",
			wantLimit:     defaultRowsLimit,
		},
		{
			name:          "negative rows falls back to default",
			raw:           "SELECT 1",
			requestedRows: -10,
			wantQuery:     "SELECT 1",
			wantLimit:     defaultRowsLimit,
		},

		// --- errors ---
		{
			name:    "empty query",
			raw:     "",
			wantErr: ErrInvalidQuery,
		},
		{
			name:    "whitespace only",
			raw:     "   \t\n  ",
			wantErr: ErrInvalidQuery,
		},
		{
			name:    "exceeds max length",
			raw:     "SELECT " + strings.Repeat("x", maxQueryLength),
			wantErr: ErrInvalidQuery,
		},
		{
			name:    "contains null byte",
			raw:     "SELECT \x00 1",
			wantErr: ErrInvalidQuery,
		},
		{
			name:    "multiple semicolons (injection attempt)",
			raw:     "SELECT 1; DROP TABLE users;",
			wantErr: ErrInvalidQuery,
		},
		{
			name:    "semicolon in the middle",
			raw:     "SELECT 1; SELECT 2",
			wantErr: ErrInvalidQuery,
		},
		{
			name:    "does not start with SELECT or WITH",
			raw:     "INSERT INTO t VALUES (1)",
			wantErr: ErrInvalidQuery,
		},
		{
			name:    "starts with UPDATE",
			raw:     "UPDATE t SET x=1",
			wantErr: ErrInvalidQuery,
		},

		// --- forbidden keywords ---
		{
			name:    "INSERT keyword",
			raw:     "SELECT * FROM (INSERT INTO t VALUES(1))",
			wantErr: ErrUnsupportedSQL,
		},
		{
			name:    "UPDATE keyword",
			raw:     "SELECT * FROM t WHERE UPDATE=1",
			wantErr: ErrUnsupportedSQL,
		},
		{
			name:    "DELETE keyword",
			raw:     "SELECT DELETE FROM t",
			wantErr: ErrUnsupportedSQL,
		},
		{
			name:    "DROP keyword",
			raw:     "SELECT 1 FROM DROP",
			wantErr: ErrUnsupportedSQL,
		},
		{
			name:    "ALTER keyword",
			raw:     "SELECT ALTER FROM t",
			wantErr: ErrUnsupportedSQL,
		},
		{
			name:    "CREATE keyword",
			raw:     "SELECT CREATE FROM t",
			wantErr: ErrUnsupportedSQL,
		},
		{
			name:    "TRUNCATE keyword",
			raw:     "SELECT TRUNCATE FROM t",
			wantErr: ErrUnsupportedSQL,
		},
		{
			name:    "EXEC keyword",
			raw:     "SELECT EXEC FROM t",
			wantErr: ErrUnsupportedSQL,
		},
		{
			name:    "EXECUTE keyword",
			raw:     "SELECT EXECUTE FROM t",
			wantErr: ErrUnsupportedSQL,
		},
		{
			name:    "COPY keyword",
			raw:     "SELECT COPY FROM t",
			wantErr: ErrUnsupportedSQL,
		},
		{
			name:    "GRANT keyword",
			raw:     "SELECT GRANT FROM t",
			wantErr: ErrUnsupportedSQL,
		},
		{
			name:    "REVOKE keyword",
			raw:     "SELECT REVOKE FROM t",
			wantErr: ErrUnsupportedSQL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotQuery, gotLimit, err := sanitizeQuery(tt.raw, tt.requestedRows)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if err != tt.wantErr {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotQuery != tt.wantQuery {
				t.Errorf("query = %q, want %q", gotQuery, tt.wantQuery)
			}
			if gotLimit != tt.wantLimit {
				t.Errorf("limit = %d, want %d", gotLimit, tt.wantLimit)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// normalizeSourceName
// ---------------------------------------------------------------------------

func TestNormalizeSourceName(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{"simple lowercase", "mydb", "mydb", false},
		{"uppercase converted", "MyDB", "mydb", false},
		{"with dots and dashes", "my.db-1", "my.db-1", false},
		{"with underscore", "my_db", "my_db", false},
		{"trimmed", "  mydb  ", "mydb", false},
		{"max length 64 chars", strings.Repeat("a", 64), strings.Repeat("a", 64), false},
		{"too long 65 chars", strings.Repeat("a", 65), "", true},
		{"empty string", "", "", true},
		{"whitespace only", "   ", "", true},
		{"special chars rejected", "my@db", "", true},
		{"spaces in name rejected", "my db", "", true},
		{"slash rejected", "my/db", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeSourceName(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseSourceMap
// ---------------------------------------------------------------------------

func TestParseSourceMap(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantNames []string
		wantErrs  int // expected number of errors
	}{
		{
			name:      "empty string",
			raw:       "",
			wantNames: nil,
		},
		{
			name:      "whitespace only",
			raw:       "   ",
			wantNames: nil,
		},
		{
			name:      "single source",
			raw:       "mydb=postgres://localhost/mydb",
			wantNames: []string{"mydb"},
		},
		{
			name:      "multiple sources",
			raw:       "db1=postgres://localhost/db1,db2=postgres://localhost/db2",
			wantNames: []string{"db1", "db2"},
		},
		{
			name:      "duplicate name reports error",
			raw:       "mydb=postgres://localhost/a,mydb=postgres://localhost/b",
			wantNames: []string{"mydb"},
			wantErrs:  1,
		},
		{
			name:      "invalid entry reports error",
			raw:       "invalid-no-equals",
			wantNames: nil,
			wantErrs:  1,
		},
		{
			name:      "mixed valid and invalid",
			raw:       "ok=postgres://localhost/ok,bad",
			wantNames: []string{"ok"},
			wantErrs:  1,
		},
		{
			name:      "invalid DSN scheme reports error",
			raw:       "mydb=mysql://localhost/mydb",
			wantNames: nil,
			wantErrs:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, errs := parseSourceMap(tt.raw)

			if len(errs) != tt.wantErrs {
				t.Errorf("errors count = %d, want %d; errs: %v", len(errs), tt.wantErrs, errs)
			}

			if tt.wantNames == nil {
				if len(got) != 0 {
					t.Errorf("expected empty map, got %v", got)
				}
				return
			}

			for _, name := range tt.wantNames {
				if _, ok := got[name]; !ok {
					t.Errorf("expected source %q in result", name)
				}
			}
			if len(got) != len(tt.wantNames) {
				t.Errorf("got %d sources, want %d", len(got), len(tt.wantNames))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseSourceSpec
// ---------------------------------------------------------------------------

func TestParseSourceSpec(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantN   string
		wantDSN string
		wantErr bool
	}{
		{
			name:    "valid spec",
			raw:     "mydb=postgres://localhost/mydb",
			wantN:   "mydb",
			wantDSN: "postgres://localhost/mydb",
		},
		{
			name:    "DSN with equals in password",
			raw:     "mydb=postgres://user:p%3Dass@localhost/mydb",
			wantN:   "mydb",
			wantDSN: "postgres://user:p%3Dass@localhost/mydb",
		},
		{
			name:    "postgresql scheme",
			raw:     "mydb=postgresql://localhost/mydb",
			wantN:   "mydb",
			wantDSN: "postgresql://localhost/mydb",
		},
		{
			name:    "empty string",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "no equals sign",
			raw:     "noequalssign",
			wantErr: true,
		},
		{
			name:    "invalid name",
			raw:     "bad name=postgres://localhost/db",
			wantErr: true,
		},
		{
			name:    "empty DSN",
			raw:     "mydb=",
			wantErr: true,
		},
		{
			name:    "invalid DSN scheme",
			raw:     "mydb=mysql://localhost/db",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, dsn, err := parseSourceSpec(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if name != tt.wantN {
				t.Errorf("name = %q, want %q", name, tt.wantN)
			}
			if dsn != tt.wantDSN {
				t.Errorf("dsn = %q, want %q", dsn, tt.wantDSN)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateDSN
// ---------------------------------------------------------------------------

func TestValidateDSN(t *testing.T) {
	tests := []struct {
		name    string
		dsn     string
		wantErr bool
	}{
		{"postgres scheme", "postgres://localhost/mydb", false},
		{"postgresql scheme", "postgresql://localhost:5432/mydb", false},
		{"postgres with user info", "postgres://user:pass@host:5432/db?sslmode=disable", false},
		{"mysql rejected", "mysql://localhost/db", true},
		{"http rejected", "http://localhost/db", true},
		{"no host", "postgres:///mydb", true},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDSN(tt.dsn)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// normalizeRowValue
// ---------------------------------------------------------------------------

type testStringer struct{ val string }

func (s testStringer) String() string { return s.val }

func TestNormalizeRowValue(t *testing.T) {
	fixedTime := time.Date(2024, 6, 15, 12, 30, 0, 0, time.UTC)

	tests := []struct {
		name string
		in   any
		want any
	}{
		{"nil", nil, nil},
		{"byte slice", []byte("hello"), "hello"},
		{"empty byte slice", []byte{}, ""},
		{"time.Time", fixedTime, "2024-06-15T12:30:00Z"},
		{"stringer", testStringer{val: "custom"}, "custom"},
		{"int", 42, "42"},
		{"float64", 3.14, "3.14"},
		{"bool", true, "true"},
		{"string via Sprintf", "plain", "plain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeRowValue(tt.in)
			if got != tt.want {
				t.Errorf("got %v (%T), want %v (%T)", got, got, tt.want, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ListSources on nil manager
// ---------------------------------------------------------------------------

func TestListSourcesNilManager(t *testing.T) {
	var m *Manager
	result := m.ListSources()
	if result == nil {
		t.Fatal("expected non-nil empty slice, got nil")
	}
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// Close on nil manager
// ---------------------------------------------------------------------------

func TestCloseNilManager(t *testing.T) {
	var m *Manager
	err := m.Close()
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Edge cases: sanitizeQuery boundary lengths
// ---------------------------------------------------------------------------

func TestSanitizeQueryBoundaryLength(t *testing.T) {
	// Exactly at maxQueryLength should pass
	q := "SELECT " + strings.Repeat("x", maxQueryLength-7) // "SELECT " is 7 chars
	if len(q) != maxQueryLength {
		t.Fatalf("test setup: expected len %d, got %d", maxQueryLength, len(q))
	}
	_, _, err := sanitizeQuery(q, 0)
	if err != nil {
		t.Errorf("query at exact max length should be valid, got: %v", err)
	}

	// One over should fail
	q2 := q + "y"
	_, _, err = sanitizeQuery(q2, 0)
	if err != ErrInvalidQuery {
		t.Errorf("query over max length: expected ErrInvalidQuery, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Edge case: sanitizeQuery with only semicolons
// ---------------------------------------------------------------------------

func TestSanitizeQueryOnlySemicolon(t *testing.T) {
	_, _, err := sanitizeQuery(";", 0)
	if err != ErrInvalidQuery {
		t.Errorf("expected ErrInvalidQuery for bare semicolon, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// normalizeRowValue: verify time zone is preserved in RFC3339
// ---------------------------------------------------------------------------

func TestNormalizeRowValueTimeWithTimezone(t *testing.T) {
	loc := time.FixedZone("EST", -5*60*60)
	ts := time.Date(2024, 1, 15, 10, 0, 0, 0, loc)
	got := normalizeRowValue(ts)
	want := ts.Format(time.RFC3339)
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// sanitizeQuery: forbidden keyword case insensitivity
// ---------------------------------------------------------------------------

func TestSanitizeQueryForbiddenCaseInsensitive(t *testing.T) {
	cases := []string{
		"SELECT insert FROM t",
		"SELECT Insert FROM t",
		"SELECT INSERT FROM t",
	}
	for _, q := range cases {
		t.Run(q, func(t *testing.T) {
			_, _, err := sanitizeQuery(q, 0)
			if err != ErrUnsupportedSQL {
				t.Errorf("expected ErrUnsupportedSQL for %q, got %v", q, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseSourceMap: preserves DSN with complex query params
// ---------------------------------------------------------------------------

func TestParseSourceMapComplexDSN(t *testing.T) {
	raw := "prod=postgres://user:pass@host:5432/db?sslmode=require&connect_timeout=10"
	sources, errs := parseSourceMap(raw)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	dsn, ok := sources["prod"]
	if !ok {
		t.Fatal("expected 'prod' source")
	}
	if dsn != "postgres://user:pass@host:5432/db?sslmode=require&connect_timeout=10" {
		t.Errorf("DSN mangled: %s", dsn)
	}
}

// ---------------------------------------------------------------------------
// normalizeRowValue: fmt.Stringer takes precedence check
// ---------------------------------------------------------------------------

func TestNormalizeRowValueStringerPrecedence(t *testing.T) {
	// Ensure a type implementing Stringer is handled by the Stringer case
	val := testStringer{val: "stringer-output"}
	got := normalizeRowValue(val)
	if got != "stringer-output" {
		t.Errorf("got %v, want %q", got, "stringer-output")
	}
}

// ---------------------------------------------------------------------------
// sanitizeQuery: rows limit at exact boundary
// ---------------------------------------------------------------------------

func TestSanitizeQueryRowsExactMax(t *testing.T) {
	_, limit, err := sanitizeQuery("SELECT 1", maxRowsLimit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if limit != maxRowsLimit {
		t.Errorf("limit = %d, want %d", limit, maxRowsLimit)
	}
}

func TestSanitizeQueryRowsOneOverMax(t *testing.T) {
	_, limit, err := sanitizeQuery("SELECT 1", maxRowsLimit+1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if limit != maxRowsLimit {
		t.Errorf("limit = %d, want %d (should be clamped)", limit, maxRowsLimit)
	}
}

// ---------------------------------------------------------------------------
// validateDSN: edge case with only scheme
// ---------------------------------------------------------------------------

func TestValidateDSNSchemeOnly(t *testing.T) {
	err := validateDSN("postgres://")
	if err == nil {
		t.Fatal("expected error for scheme-only DSN")
	}
	_ = fmt.Sprintf("error: %v", err) // ensure error is non-nil and printable
}

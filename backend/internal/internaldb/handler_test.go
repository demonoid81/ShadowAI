package internaldb

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
)

// ---------------------------------------------------------------------------
// maskDSN
// ---------------------------------------------------------------------------

func TestMaskDSN_ValidPostgresWithUserPass(t *testing.T) {
	raw := "postgres://admin:secret@localhost:5432/mydb?sslmode=disable"
	got := maskDSN(raw)

	if strings.Contains(got, "admin") || strings.Contains(got, "secret") {
		t.Fatalf("credentials not masked: %s", got)
	}
	// url.UserPassword encodes * as %2A
	if !strings.Contains(got, "%2A%2A%2A:%2A%2A%2A") && !strings.Contains(got, "***:***") {
		t.Fatalf("expected masked credentials in DSN, got: %s", got)
	}
	if !strings.Contains(got, "localhost:5432") {
		t.Fatalf("host should be preserved, got: %s", got)
	}
}

func TestMaskDSN_NoUserInfo(t *testing.T) {
	raw := "postgres://localhost:5432/mydb"
	got := maskDSN(raw)

	if !strings.Contains(got, "localhost:5432") {
		t.Fatalf("host should be preserved, got: %s", got)
	}
	if strings.Contains(got, "***") {
		t.Fatalf("should not contain *** when no user info, got: %s", got)
	}
}

func TestMaskDSN_InvalidURL(t *testing.T) {
	got := maskDSN("://bad url\x00")
	if got != "[invalid-dsn]" {
		t.Fatalf("expected [invalid-dsn], got: %s", got)
	}
}

// ---------------------------------------------------------------------------
// parseSourceID
// ---------------------------------------------------------------------------

func TestParseSourceID_ValidUUID(t *testing.T) {
	input := "550e8400-e29b-41d4-a716-446655440000"
	id, err := parseSourceID(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != input {
		t.Fatalf("expected %s, got %s", input, id)
	}
}

func TestParseSourceID_Invalid(t *testing.T) {
	_, err := parseSourceID("not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid UUID")
	}
}

func TestParseSourceID_Empty(t *testing.T) {
	_, err := parseSourceID("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}

// ---------------------------------------------------------------------------
// isNotFoundError
// ---------------------------------------------------------------------------

func TestIsNotFoundError_Nil(t *testing.T) {
	if isNotFoundError(nil) {
		t.Fatal("nil should return false")
	}
}

func TestIsNotFoundError_SqlErrNoRows(t *testing.T) {
	if !isNotFoundError(sql.ErrNoRows) {
		t.Fatal("sql.ErrNoRows should return true")
	}
}

func TestIsNotFoundError_WrappedSqlErrNoRows(t *testing.T) {
	wrapped := errors.New("query failed: " + sql.ErrNoRows.Error())
	// The function uses errors.Is, so a simple string wrap won't match.
	// Test with fmt.Errorf wrapping instead.
	wrappedProper := errors.Join(errors.New("query failed"), sql.ErrNoRows)
	if !isNotFoundError(wrappedProper) {
		t.Fatal("wrapped sql.ErrNoRows should return true")
	}
	_ = wrapped
}

func TestIsNotFoundError_NotFoundInMessage(t *testing.T) {
	err := errors.New("source not found in registry")
	if !isNotFoundError(err) {
		t.Fatal("error containing 'not found' should return true")
	}
}

func TestIsNotFoundError_NotFoundCaseInsensitive(t *testing.T) {
	err := errors.New("Source Not Found")
	if !isNotFoundError(err) {
		t.Fatal("error containing 'Not Found' (case-insensitive) should return true")
	}
}

func TestIsNotFoundError_OtherError(t *testing.T) {
	err := errors.New("connection refused")
	if isNotFoundError(err) {
		t.Fatal("unrelated error should return false")
	}
}

// ---------------------------------------------------------------------------
// isUniqueConstraintError
// ---------------------------------------------------------------------------

func TestIsUniqueConstraintError_Nil(t *testing.T) {
	if isUniqueConstraintError(nil) {
		t.Fatal("nil should return false")
	}
}

func TestIsUniqueConstraintError_PqError23505(t *testing.T) {
	err := &pq.Error{Code: "23505"}
	if !isUniqueConstraintError(err) {
		t.Fatal("pq.Error with code 23505 should return true")
	}
}

func TestIsUniqueConstraintError_OtherPqError(t *testing.T) {
	err := &pq.Error{Code: "23503"} // foreign key violation
	if isUniqueConstraintError(err) {
		t.Fatal("pq.Error with code 23503 should return false")
	}
}

func TestIsUniqueConstraintError_GenericError(t *testing.T) {
	err := errors.New("duplicate key value")
	if isUniqueConstraintError(err) {
		t.Fatal("generic error should return false")
	}
}

// ---------------------------------------------------------------------------
// marshalAuditPayload
// ---------------------------------------------------------------------------

func TestMarshalAuditPayload_ValidMap(t *testing.T) {
	payload := map[string]interface{}{
		"id":   "abc",
		"name": "test",
	}
	got := marshalAuditPayload(payload)
	if got == "{}" {
		t.Fatal("should not return empty JSON for valid map")
	}
	if !strings.Contains(got, `"id"`) || !strings.Contains(got, `"abc"`) {
		t.Fatalf("expected id/abc in output, got: %s", got)
	}
}

func TestMarshalAuditPayload_EmptyMap(t *testing.T) {
	got := marshalAuditPayload(map[string]interface{}{})
	if got != "{}" {
		t.Fatalf("expected {}, got: %s", got)
	}
}

// ---------------------------------------------------------------------------
// auditRequestPayload
// ---------------------------------------------------------------------------

func TestAuditRequestPayload_Empty(t *testing.T) {
	got := auditRequestPayload("")
	if got != "" {
		t.Fatalf("expected empty string, got: %s", got)
	}
}

func TestAuditRequestPayload_ShortText(t *testing.T) {
	input := "SELECT * FROM users"
	got := auditRequestPayload(input)
	if got != input {
		t.Fatalf("short text without PII should be unchanged, got: %s", got)
	}
}

func TestAuditRequestPayload_EmailRedacted(t *testing.T) {
	input := "SELECT * FROM users WHERE email = 'test@example.com'"
	got := auditRequestPayload(input)
	if strings.Contains(got, "test@example.com") {
		t.Fatalf("email should be redacted, got: %s", got)
	}
	if !strings.Contains(got, "[redacted:") {
		t.Fatalf("should contain [redacted: marker, got: %s", got)
	}
}

func TestAuditRequestPayload_LongTextTruncated(t *testing.T) {
	input := strings.Repeat("a", 3000)
	got := auditRequestPayload(input)
	if len(got) > 2004 { // 2000 + len("...")
		t.Fatalf("expected truncation to ~2003 chars, got length: %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("expected '...' suffix, got: %s", got[len(got)-10:])
	}
}

// ---------------------------------------------------------------------------
// sourceAdminResponseFor
// ---------------------------------------------------------------------------

func TestSourceAdminResponseFor_MapsAllFields(t *testing.T) {
	now := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	source := InternalDBSource{
		ID:          "550e8400-e29b-41d4-a716-446655440000",
		Name:        "test-source",
		DSN:         "postgres://user:pass@localhost:5432/testdb",
		Description: "A test source",
		IsActive:    true,
		CreatedAt:   now,
		UpdatedAt:   now.Add(time.Hour),
	}

	resp := sourceAdminResponseFor(source)

	if resp.ID != source.ID {
		t.Fatalf("ID mismatch: %s vs %s", resp.ID, source.ID)
	}
	if resp.Name != source.Name {
		t.Fatalf("Name mismatch: %s vs %s", resp.Name, source.Name)
	}
	if resp.Description != source.Description {
		t.Fatalf("Description mismatch: %s vs %s", resp.Description, source.Description)
	}
	if resp.IsActive != source.IsActive {
		t.Fatalf("IsActive mismatch: %v vs %v", resp.IsActive, source.IsActive)
	}
	if resp.CreatedAt != source.CreatedAt {
		t.Fatalf("CreatedAt mismatch: %v vs %v", resp.CreatedAt, source.CreatedAt)
	}
	if resp.UpdatedAt != source.UpdatedAt {
		t.Fatalf("UpdatedAt mismatch: %v vs %v", resp.UpdatedAt, source.UpdatedAt)
	}
}

func TestSourceAdminResponseFor_DSNIsMasked(t *testing.T) {
	source := InternalDBSource{
		DSN: "postgres://admin:supersecret@db.example.com:5432/prod",
	}

	resp := sourceAdminResponseFor(source)

	if strings.Contains(resp.DSNMasked, "admin") || strings.Contains(resp.DSNMasked, "supersecret") {
		t.Fatalf("DSN credentials should be masked, got: %s", resp.DSNMasked)
	}
	if !strings.Contains(resp.DSNMasked, "%2A%2A%2A:%2A%2A%2A") && !strings.Contains(resp.DSNMasked, "***:***") {
		t.Fatalf("expected masked credentials in DSN, got: %s", resp.DSNMasked)
	}
}

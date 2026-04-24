package auth

import (
	"encoding/json"
	"testing"
)

// Tests for optionalString — distinguishes absent / null / string in JSON.

// TestOptionalString_Absent — field not present in JSON → Set==false (no change).
func TestOptionalString_Absent(t *testing.T) {
	var req struct {
		Department optionalString `json:"department"`
	}
	if err := json.Unmarshal([]byte(`{}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Department.Set {
		t.Error("absent field: Set must be false")
	}
	if req.Department.Value != nil {
		t.Errorf("absent field: Value must be nil, got %v", req.Department.Value)
	}
}

// TestOptionalString_Null — explicit null in JSON → Set==true, Value==nil (clear).
func TestOptionalString_Null(t *testing.T) {
	var req struct {
		Department optionalString `json:"department"`
	}
	if err := json.Unmarshal([]byte(`{"department":null}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !req.Department.Set {
		t.Error("null field: Set must be true")
	}
	if req.Department.Value != nil {
		t.Errorf("null field: Value must be nil (clear semantics), got %v", req.Department.Value)
	}
}

// TestOptionalString_String — string value in JSON → Set==true, Value==&str (set).
func TestOptionalString_String(t *testing.T) {
	var req struct {
		Department optionalString `json:"department"`
	}
	if err := json.Unmarshal([]byte(`{"department":"finance"}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !req.Department.Set {
		t.Error("string field: Set must be true")
	}
	if req.Department.Value == nil {
		t.Fatal("string field: Value must not be nil")
	}
	if *req.Department.Value != "finance" {
		t.Errorf("Value = %q, want finance", *req.Department.Value)
	}
}

// TestOptionalString_EmptyString — empty string is distinct from null.
func TestOptionalString_EmptyString(t *testing.T) {
	var req struct {
		Department optionalString `json:"department"`
	}
	if err := json.Unmarshal([]byte(`{"department":""}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !req.Department.Set {
		t.Error("empty string field: Set must be true")
	}
	if req.Department.Value == nil {
		t.Fatal("empty string: Value must not be nil (distinct from null)")
	}
	if *req.Department.Value != "" {
		t.Errorf("Value = %q, want empty string", *req.Department.Value)
	}
}

// TestOptionalString_AbsentDoesNotChangeTarget — regression: absent field
// must not overwrite an existing department value.
func TestOptionalString_AbsentDoesNotChangeTarget(t *testing.T) {
	var req struct {
		Department optionalString `json:"department"`
	}
	if err := json.Unmarshal([]byte(`{"email":"user@example.com"}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Simulate what UpdateUser handler does with req.Department.
	existing := "legal" // current department
	var target *string = &existing

	if req.Department.Set {
		target = req.Department.Value
	}
	// target must still point to "legal" since field was absent.
	if target == nil || *target != "legal" {
		t.Errorf("absent field changed target: got %v, want legal", target)
	}
}

// TestOptionalString_NullClearsTarget — regression: explicit null must clear.
func TestOptionalString_NullClearsTarget(t *testing.T) {
	var req struct {
		Department optionalString `json:"department"`
	}
	if err := json.Unmarshal([]byte(`{"department":null}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	existing := "legal"
	var target *string = &existing

	if req.Department.Set {
		target = req.Department.Value
	}
	if target != nil {
		t.Errorf("null field must clear target: got %q, want nil", *target)
	}
}

// TestOptionalString_StringSetsTarget — regression: string must set target.
func TestOptionalString_StringSetsTarget(t *testing.T) {
	var req struct {
		Department optionalString `json:"department"`
	}
	if err := json.Unmarshal([]byte(`{"department":"finance"}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	var target *string // initially nil

	if req.Department.Set {
		target = req.Department.Value
	}
	if target == nil || *target != "finance" {
		t.Errorf("string field must set target to 'finance': got %v", target)
	}
}

package legalholdselector

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCompile_EquivalentSelectorsStableHash(t *testing.T) {
	a := json.RawMessage(`{
		"v":1,
		"all":[
			{"field":"provider","op":"in","value":["anthropic","openai","openai"]},
			{"field":"policy_action","op":"eq","value":"blocked"}
		]
	}`)
	b := json.RawMessage(`{
		"all":[
			{"op":"eq","field":"policy_action","value":"blocked"},
			{"value":["openai","anthropic"],"op":"in","field":"provider"}
		],
		"v":1
	}`)

	ca, err := Compile(a, CompileOptions{})
	if err != nil {
		t.Fatalf("compile a: %v", err)
	}
	cb, err := Compile(b, CompileOptions{})
	if err != nil {
		t.Fatalf("compile b: %v", err)
	}
	if ca.Hash != cb.Hash {
		t.Fatalf("hash mismatch: %s != %s", ca.Hash, cb.Hash)
	}
	if string(ca.NormalizedJSON) != string(cb.NormalizedJSON) {
		t.Fatalf("normalized mismatch:\n%s\n%s", ca.NormalizedJSON, cb.NormalizedJSON)
	}
	if !strings.Contains(ca.Explanation, "provider in [anthropic,openai]") {
		t.Fatalf("explanation = %q", ca.Explanation)
	}
}

func TestCompile_RejectsTenantBoundaryFields(t *testing.T) {
	_, err := Compile(json.RawMessage(`{"v":1,"field":"org_id","op":"eq","value":"org-a"}`), CompileOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsInvalid(err) {
		t.Fatalf("IsInvalid=false for %v", err)
	}
}

func TestCompile_RejectsInvalidOperator(t *testing.T) {
	_, err := Compile(json.RawMessage(`{"v":1,"field":"provider","op":"between","value":["a","b"]}`), CompileOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCompile_RejectsMissingVersion(t *testing.T) {
	_, err := Compile(json.RawMessage(`{"field":"provider","op":"eq","value":"openai"}`), CompileOptions{})
	if err == nil {
		t.Fatal("expected missing version error")
	}
}

func TestCompile_RejectsUnknownKeys(t *testing.T) {
	_, err := Compile(json.RawMessage(`{"v":1,"field":"provider","op":"eq","value":"openai","not":true}`), CompileOptions{})
	if err == nil {
		t.Fatal("expected unknown key error")
	}
}

func TestCompile_RejectsIgnoredGroupKeys(t *testing.T) {
	_, err := Compile(json.RawMessage(`{"v":1,"all":[{"field":"provider","op":"eq","value":"openai"}],"op":"eq"}`), CompileOptions{})
	if err == nil {
		t.Fatal("expected ignored group key error")
	}
}

func TestCompile_RejectsOverLargeInList(t *testing.T) {
	values := make([]string, maxInList+1)
	for i := range values {
		values[i] = "x"
	}
	raw, err := json.Marshal(map[string]any{
		"v":     1,
		"field": "provider",
		"op":    "in",
		"value": values,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := Compile(raw, CompileOptions{}); err == nil {
		t.Fatal("expected max in-list error")
	}
}

func TestCompile_RejectsTooDeepTree(t *testing.T) {
	raw := json.RawMessage(`{"v":1,"all":[{"any":[{"all":[{"field":"provider","op":"eq","value":"openai"}]}]}]}`)
	if _, err := Compile(raw, CompileOptions{}); err == nil {
		t.Fatal("expected depth error")
	}
}

func TestCompile_SQLIsParameterized(t *testing.T) {
	raw := json.RawMessage(`{"v":1,"field":"provider","op":"eq","value":"openai' OR true --"}`)
	c, err := Compile(raw, CompileOptions{ArgOffset: 3})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(c.SQL, "openai") || strings.Contains(c.SQL, "true") {
		t.Fatalf("SQL includes raw value: %s", c.SQL)
	}
	if !strings.Contains(c.SQL, "$3") {
		t.Fatalf("SQL = %s, want $3 placeholder", c.SQL)
	}
	if len(c.Args) != 1 || c.Args[0] != "openai' OR true --" {
		t.Fatalf("args = %#v", c.Args)
	}
}

func TestCompile_CreatedAtBetweenUTCArgs(t *testing.T) {
	raw := json.RawMessage(`{"v":1,"field":"created_at","op":"between","value":["2026-04-02T02:00:00+02:00","2026-04-02T03:00:00+02:00"]}`)
	c, err := Compile(raw, CompileOptions{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(c.Args) != 2 {
		t.Fatalf("args = %#v", c.Args)
	}
	got := c.Args[0].(time.Time).Format(time.RFC3339)
	if got != "2026-04-02T00:00:00Z" {
		t.Fatalf("first arg = %s", got)
	}
	if !strings.Contains(string(c.NormalizedJSON), "2026-04-02T00:00:00Z") {
		t.Fatalf("normalized = %s", c.NormalizedJSON)
	}
}

func TestCompile_OutcomeIsEmpty(t *testing.T) {
	c, err := Compile(json.RawMessage(`{"v":1,"field":"outcome","op":"is_empty"}`), CompileOptions{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if c.SQL != "(outcome IS NULL OR outcome = '')" {
		t.Fatalf("SQL = %s", c.SQL)
	}
	if len(c.Args) != 0 {
		t.Fatalf("args = %#v", c.Args)
	}
}

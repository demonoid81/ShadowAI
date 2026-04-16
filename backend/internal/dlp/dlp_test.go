package dlp

import (
	"strings"
	"testing"

	"github.com/shadowai/backend/internal/pii"
)

// ---------------------------------------------------------------------------
// 1. normalizeMode via NewService
// ---------------------------------------------------------------------------

func TestNewService_NormalizeMode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantMode Mode
	}{
		{"audit lowercase", "audit", DLPModeAudit},
		{"enforce lowercase", "enforce", DLPModeEnforce},
		{"strict lowercase", "strict", DLPModeStrict},
		{"audit uppercase", "AUDIT", DLPModeAudit},
		{"enforce mixed case", "Enforce", DLPModeEnforce},
		{"strict with spaces", "  strict  ", DLPModeStrict},
		{"unknown defaults to enforce", "unknown", DLPModeEnforce},
		{"empty defaults to enforce", "", DLPModeEnforce},
		{"gibberish defaults to enforce", "foobar", DLPModeEnforce},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewService(tt.input)
			if svc.mode != tt.wantMode {
				t.Errorf("NewService(%q).mode = %q, want %q", tt.input, svc.mode, tt.wantMode)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. Evaluate with no findings => allowed
// ---------------------------------------------------------------------------

func TestEvaluate_NoFindings(t *testing.T) {
	for _, mode := range []string{"audit", "enforce", "strict"} {
		t.Run(mode, func(t *testing.T) {
			svc := NewService(mode)
			dec := svc.Evaluate("hello world", nil)
			if dec.Action != DLPActionAllow {
				t.Errorf("mode=%s: expected allowed, got %s", mode, dec.Action)
			}
			if len(dec.Findings) != 0 {
				t.Errorf("mode=%s: expected 0 findings, got %d", mode, len(dec.Findings))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. Evaluate with PII findings — severity mapping
// ---------------------------------------------------------------------------

func TestEvaluate_PIISeverityMapping(t *testing.T) {
	tests := []struct {
		piiType      string
		wantSeverity Severity
	}{
		{"email", SeverityMedium},
		{"ssn", SeverityHigh},
		{"credit_card", SeverityHigh},
		{"phone", SeverityMedium},
		{"ip_address", SeverityMedium},
		{"unknown_type", SeverityMedium}, // default
	}

	for _, tt := range tests {
		t.Run(tt.piiType, func(t *testing.T) {
			svc := NewService("audit") // audit so we always get findings back without blocking
			text := "some text with data"
			piiFindings := []pii.Finding{
				{Type: tt.piiType, Match: "data", Start: 15, End: 19},
			}
			dec := svc.Evaluate(text, piiFindings)
			if len(dec.Findings) == 0 {
				t.Fatal("expected at least one finding")
			}
			found := false
			for _, f := range dec.Findings {
				if f.Type == tt.piiType {
					found = true
					if f.Severity != tt.wantSeverity {
						t.Errorf("type=%s: severity = %q, want %q", tt.piiType, f.Severity, tt.wantSeverity)
					}
				}
			}
			if !found {
				t.Errorf("finding with type %q not found in results", tt.piiType)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 4. Evaluate in audit mode => always allowed regardless of findings
// ---------------------------------------------------------------------------

func TestEvaluate_AuditMode_AlwaysAllowed(t *testing.T) {
	svc := NewService("audit")
	text := "my ssn is 123-45-6789"
	piiFindings := []pii.Finding{
		{Type: "ssn", Match: "123-45-6789", Start: 10, End: 21},
	}
	dec := svc.Evaluate(text, piiFindings)
	if dec.Action != DLPActionAllow {
		t.Errorf("audit mode should always allow, got %s", dec.Action)
	}
	if len(dec.Findings) == 0 {
		t.Error("audit mode should still report findings")
	}
}

func TestEvaluate_AuditMode_WithHighSeverity(t *testing.T) {
	svc := NewService("audit")
	text := "key: sk-abcdefghij1234567890abcd"
	dec := svc.Evaluate(text, nil)
	if dec.Action != DLPActionAllow {
		t.Errorf("audit mode with secrets should still allow, got %s", dec.Action)
	}
}

// ---------------------------------------------------------------------------
// 5. Evaluate in enforce mode => block on high, sanitize on medium
// ---------------------------------------------------------------------------

func TestEvaluate_EnforceMode_HighSeverity_Blocked(t *testing.T) {
	svc := NewService("enforce")
	text := "my ssn is 123-45-6789"
	piiFindings := []pii.Finding{
		{Type: "ssn", Match: "123-45-6789", Start: 10, End: 21},
	}
	dec := svc.Evaluate(text, piiFindings)
	if dec.Action != DLPActionBlock {
		t.Errorf("enforce mode with high severity: expected blocked, got %s", dec.Action)
	}
}

func TestEvaluate_EnforceMode_MediumSeverity_Sanitized(t *testing.T) {
	svc := NewService("enforce")
	text := "email is user@test.com here"
	piiFindings := []pii.Finding{
		{Type: "email", Match: "user@test.com", Start: 9, End: 22},
	}
	dec := svc.Evaluate(text, piiFindings)
	if dec.Action != DLPActionSanitize {
		t.Errorf("enforce mode with medium severity: expected sanitized, got %s", dec.Action)
	}
}

func TestEvaluate_EnforceMode_LowSeverity_Allowed(t *testing.T) {
	svc := NewService("enforce")
	// No PII, no secrets => low/no findings => allowed
	text := "just a normal message"
	dec := svc.Evaluate(text, nil)
	if dec.Action != DLPActionAllow {
		t.Errorf("enforce mode with no findings: expected allowed, got %s", dec.Action)
	}
}

// ---------------------------------------------------------------------------
// 6. Evaluate in strict mode => block on medium too
// ---------------------------------------------------------------------------

func TestEvaluate_StrictMode_MediumSeverity_Blocked(t *testing.T) {
	svc := NewService("strict")
	text := "email is user@test.com here"
	piiFindings := []pii.Finding{
		{Type: "email", Match: "user@test.com", Start: 9, End: 22},
	}
	dec := svc.Evaluate(text, piiFindings)
	if dec.Action != DLPActionBlock {
		t.Errorf("strict mode with medium severity: expected blocked, got %s", dec.Action)
	}
}

func TestEvaluate_StrictMode_HighSeverity_Blocked(t *testing.T) {
	svc := NewService("strict")
	text := "my ssn is 123-45-6789"
	piiFindings := []pii.Finding{
		{Type: "ssn", Match: "123-45-6789", Start: 10, End: 21},
	}
	dec := svc.Evaluate(text, piiFindings)
	if dec.Action != DLPActionBlock {
		t.Errorf("strict mode with high severity: expected blocked, got %s", dec.Action)
	}
}

// ---------------------------------------------------------------------------
// 7. Secret pattern detection
// ---------------------------------------------------------------------------

func TestSecretDetection(t *testing.T) {
	tests := []struct {
		name       string
		text       string
		wantType   string
		wantFound  bool
	}{
		{
			name:      "OpenAI API key",
			text:      "my key is sk-abcdefghijklmnopqrstuvwx",
			wantType:  "openai_api_key",
			wantFound: true,
		},
		{
			name:      "AWS access key",
			text:      "aws key AKIAIOSFODNN7EXAMPLE",
			wantType:  "aws_access_key",
			wantFound: true,
		},
		{
			name:      "GitHub token ghp_",
			text:      "token ghp_ABCDEFGHIJKLMNOPQRSTuvwx",
			wantType:  "github_token",
			wantFound: true,
		},
		{
			name:      "GitHub token gho_",
			text:      "token gho_ABCDEFGHIJKLMNOPQRSTuvwx",
			wantType:  "github_token",
			wantFound: true,
		},
		{
			name:      "Bearer token",
			text:      "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
			wantType:  "bearer_token",
			wantFound: true,
		},
		{
			name:      "Private key header",
			text:      "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKc\n-----END RSA PRIVATE KEY-----",
			wantType:  "private_key",
			wantFound: true,
		},
		{
			name:      "Private key EC",
			text:      "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBvJpaoPe/abcdefgh\n-----END EC PRIVATE KEY-----",
			wantType:  "private_key",
			wantFound: true,
		},
		{
			name:      "Anthropic API key",
			text:      "key is sk-ant-api03-abcdefghij",
			wantType:  "anthropic_api_key",
			wantFound: true,
		},
		{
			name:      "API secret with equals",
			text:      "api_secret=ABCDEFGHIJKLMNOP1234",
			wantType:  "api_secret",
			wantFound: true,
		},
		{
			name:      "No secret in clean text",
			text:      "this is a perfectly normal message",
			wantType:  "",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewService("audit")
			dec := svc.Evaluate(tt.text, nil)
			if !tt.wantFound {
				if len(dec.Findings) != 0 {
					t.Errorf("expected no findings, got %d: %+v", len(dec.Findings), dec.Findings)
				}
				return
			}
			found := false
			for _, f := range dec.Findings {
				if f.Type == tt.wantType {
					found = true
					if f.Severity != SeverityHigh {
						t.Errorf("secret %s should be high severity, got %s", tt.wantType, f.Severity)
					}
				}
			}
			if !found {
				types := make([]string, 0, len(dec.Findings))
				for _, f := range dec.Findings {
					types = append(types, f.Type)
				}
				t.Errorf("expected finding type %q, got types: %v", tt.wantType, types)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 8. Sanitize replaces matched text with [redacted:type]
// ---------------------------------------------------------------------------

func TestSanitize_ReplacesWithRedacted(t *testing.T) {
	svc := NewService("enforce")
	text := "email is user@test.com here"
	piiFindings := []pii.Finding{
		{Type: "email", Match: "user@test.com", Start: 9, End: 22},
	}
	result := svc.Sanitize(text, piiFindings)
	if !strings.Contains(result, "[redacted:email]") {
		t.Errorf("expected [redacted:email] in result, got: %s", result)
	}
	if strings.Contains(result, "user@test.com") {
		t.Errorf("original email should be removed, got: %s", result)
	}
}

func TestSanitize_MultipleFindings(t *testing.T) {
	svc := NewService("enforce")
	text := "aa 123-45-6789 bb user@test.com cc"
	piiFindings := []pii.Finding{
		{Type: "ssn", Match: "123-45-6789", Start: 3, End: 14},
		{Type: "email", Match: "user@test.com", Start: 18, End: 31},
	}
	result := svc.Sanitize(text, piiFindings)
	if !strings.Contains(result, "[redacted:ssn]") {
		t.Errorf("expected [redacted:ssn], got: %s", result)
	}
	if !strings.Contains(result, "[redacted:email]") {
		t.Errorf("expected [redacted:email], got: %s", result)
	}
}

func TestSanitize_SecretDetection(t *testing.T) {
	svc := NewService("enforce")
	text := "my key sk-abcdefghijklmnopqrstuvwx is here"
	result := svc.Sanitize(text, nil)
	if !strings.Contains(result, "[redacted:openai_api_key]") {
		t.Errorf("expected [redacted:openai_api_key], got: %s", result)
	}
	if strings.Contains(result, "sk-abcdefghijklmnopqrstuvwx") {
		t.Errorf("secret should be redacted, got: %s", result)
	}
}

func TestSanitize_EmptyText(t *testing.T) {
	svc := NewService("enforce")
	result := svc.Sanitize("", nil)
	if result != "" {
		t.Errorf("expected empty string, got: %q", result)
	}
}

func TestSanitize_NoFindings(t *testing.T) {
	svc := NewService("enforce")
	text := "just normal text"
	result := svc.Sanitize(text, nil)
	if result != text {
		t.Errorf("expected unchanged text, got: %q", result)
	}
}

// ---------------------------------------------------------------------------
// 9. Types returns unique types from findings
// ---------------------------------------------------------------------------

func TestTypes_UniqueTypes(t *testing.T) {
	svc := NewService("enforce")
	findings := []Finding{
		{Type: "email", Severity: SeverityMedium},
		{Type: "ssn", Severity: SeverityHigh},
		{Type: "email", Severity: SeverityMedium},
		{Type: "phone", Severity: SeverityMedium},
		{Type: "ssn", Severity: SeverityHigh},
	}
	types := svc.Types(findings)
	if len(types) != 3 {
		t.Errorf("expected 3 unique types, got %d: %v", len(types), types)
	}
	// Check order is preserved (first occurrence)
	expected := []string{"email", "ssn", "phone"}
	for i, want := range expected {
		if i >= len(types) {
			break
		}
		if types[i] != want {
			t.Errorf("types[%d] = %q, want %q", i, types[i], want)
		}
	}
}

func TestTypes_Empty(t *testing.T) {
	svc := NewService("enforce")
	types := svc.Types(nil)
	if len(types) != 0 {
		t.Errorf("expected 0 types for nil input, got %d", len(types))
	}
}

func TestTypes_SingleType(t *testing.T) {
	svc := NewService("enforce")
	findings := []Finding{
		{Type: "email", Severity: SeverityMedium},
	}
	types := svc.Types(findings)
	if len(types) != 1 || types[0] != "email" {
		t.Errorf("expected [email], got %v", types)
	}
}

// ---------------------------------------------------------------------------
// 10. Edge cases
// ---------------------------------------------------------------------------

func TestEvaluate_EmptyText(t *testing.T) {
	svc := NewService("enforce")
	dec := svc.Evaluate("", nil)
	if dec.Action != DLPActionAllow {
		t.Errorf("empty text should be allowed, got %s", dec.Action)
	}
}

func TestEvaluate_WhitespaceOnlyText(t *testing.T) {
	svc := NewService("enforce")
	// Even with findings, whitespace-only text is allowed per makeDecision logic
	piiFindings := []pii.Finding{
		{Type: "email", Match: " ", Start: 0, End: 1},
	}
	dec := svc.Evaluate(" ", piiFindings)
	if dec.Action != DLPActionAllow {
		t.Errorf("whitespace-only text should be allowed, got %s", dec.Action)
	}
}

func TestEvaluate_InvalidPIIFindingBounds(t *testing.T) {
	svc := NewService("enforce")
	text := "hello"
	piiFindings := []pii.Finding{
		{Type: "ssn", Match: "xxx", Start: -1, End: 3},     // negative start
		{Type: "ssn", Match: "xxx", Start: 3, End: 2},      // end < start
		{Type: "ssn", Match: "xxx", Start: 0, End: 100},    // end > len(text)
		{Type: "ssn", Match: "xxx", Start: 2, End: 2},      // end == start
	}
	dec := svc.Evaluate(text, piiFindings)
	if len(dec.Findings) != 0 {
		t.Errorf("expected all invalid findings to be filtered, got %d", len(dec.Findings))
	}
	if dec.Action != DLPActionAllow {
		t.Errorf("no valid findings should result in allowed, got %s", dec.Action)
	}
}

func TestEvaluate_VeryLongText(t *testing.T) {
	svc := NewService("enforce")
	// Build a long text with an embedded secret (spaces needed for \b word boundary)
	prefix := strings.Repeat("a", 10000) + " "
	secret := "sk-abcdefghijklmnopqrstuvwx"
	suffix := " " + strings.Repeat("b", 10000)
	text := prefix + secret + suffix

	dec := svc.Evaluate(text, nil)
	if dec.Action != DLPActionBlock {
		t.Errorf("long text with secret should be blocked, got %s", dec.Action)
	}
	found := false
	for _, f := range dec.Findings {
		if f.Type == "openai_api_key" {
			found = true
			if f.Start != len(prefix) {
				t.Errorf("expected start=%d, got %d", len(prefix), f.Start)
			}
		}
	}
	if !found {
		t.Error("expected openai_api_key finding in long text")
	}
}

func TestEvaluate_MultipleSecretTypes(t *testing.T) {
	svc := NewService("enforce")
	text := "keys: sk-abcdefghijklmnopqrstuvwx and AKIAIOSFODNN7EXAMPLE"
	dec := svc.Evaluate(text, nil)
	if dec.Action != DLPActionBlock {
		t.Errorf("expected blocked, got %s", dec.Action)
	}
	typeSet := make(map[string]bool)
	for _, f := range dec.Findings {
		typeSet[f.Type] = true
	}
	if !typeSet["openai_api_key"] {
		t.Error("missing openai_api_key finding")
	}
	if !typeSet["aws_access_key"] {
		t.Error("missing aws_access_key finding")
	}
}

func TestEvaluate_DecisionReasonContainsTypes(t *testing.T) {
	svc := NewService("enforce")
	text := "my ssn is 123-45-6789"
	piiFindings := []pii.Finding{
		{Type: "ssn", Match: "123-45-6789", Start: 10, End: 21},
	}
	dec := svc.Evaluate(text, piiFindings)
	if dec.Reason == "" {
		t.Error("blocked decision should have a reason")
	}
	if !strings.Contains(dec.Reason, "ssn") {
		t.Errorf("reason should mention type, got: %s", dec.Reason)
	}
}

func TestEvaluate_MixedHighAndMediumSeverity(t *testing.T) {
	svc := NewService("enforce")
	text := "ssn 123-45-6789 email user@test.com"
	piiFindings := []pii.Finding{
		{Type: "ssn", Match: "123-45-6789", Start: 4, End: 15},
		{Type: "email", Match: "user@test.com", Start: 22, End: 35},
	}
	dec := svc.Evaluate(text, piiFindings)
	// High severity takes precedence => block
	if dec.Action != DLPActionBlock {
		t.Errorf("mixed high+medium should block, got %s", dec.Action)
	}
}

func TestSanitize_PreservesTextAroundFindings(t *testing.T) {
	svc := NewService("enforce")
	text := "before user@test.com after"
	piiFindings := []pii.Finding{
		{Type: "email", Match: "user@test.com", Start: 7, End: 20},
	}
	result := svc.Sanitize(text, piiFindings)
	if !strings.HasPrefix(result, "before ") {
		t.Errorf("prefix not preserved, got: %s", result)
	}
	if !strings.HasSuffix(result, " after") {
		t.Errorf("suffix not preserved, got: %s", result)
	}
}

// ---------------------------------------------------------------------------
// Deduplication: same position and type should be deduped
// ---------------------------------------------------------------------------

func TestSanitize_FullPEMBlock(t *testing.T) {
	svc := NewService("enforce")
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC\nabcdefghijklmnopqrstuvwxyz==\n-----END RSA PRIVATE KEY-----"
	input := "here is my key: " + pem + " please use it"
	result := svc.Sanitize(input, nil)
	if strings.Contains(result, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKc") {
		t.Errorf("PEM body not redacted: %s", result)
	}
	if strings.Contains(result, "-----END RSA PRIVATE KEY-----") {
		t.Errorf("PEM footer not redacted: %s", result)
	}
	if !strings.Contains(result, "[redacted:private_key]") {
		t.Errorf("no redaction marker: %s", result)
	}
}

func TestEvaluate_DeduplicatesFindings(t *testing.T) {
	svc := NewService("audit")
	text := "data data data"
	// Two PII findings at the exact same position with same type
	piiFindings := []pii.Finding{
		{Type: "email", Match: "data", Start: 0, End: 4},
		{Type: "email", Match: "data", Start: 0, End: 4},
	}
	dec := svc.Evaluate(text, piiFindings)
	count := 0
	for _, f := range dec.Findings {
		if f.Type == "email" && f.Start == 0 && f.End == 4 {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduped finding, got %d", count)
	}
}

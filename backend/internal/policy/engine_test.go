package policy

import (
	"testing"

	"github.com/shadowai/backend/internal/domain"
)

func TestEvaluateRule(t *testing.T) {
	engine := &Engine{}

	tests := []struct {
		name     string
		rule     domain.PolicyRule
		text     string
		model    string
		piiTypes []string
		want     *EvalResult
	}{
		// pii_block
		{
			name: "pii_block matches blocked type",
			rule: domain.PolicyRule{
				Name:     "block-ssn",
				RuleType: "pii_block",
				IsActive: true,
				Config: map[string]interface{}{
					"pii_types": []any{"SSN", "CREDIT_CARD"},
				},
			},
			piiTypes: []string{"SSN"},
			want:     &EvalResult{Action: ActionBlocked, Reason: "PII detected: SSN", Rule: "block-ssn"},
		},
		{
			name: "pii_block no matching type returns nil",
			rule: domain.PolicyRule{
				Name:     "block-ssn",
				RuleType: "pii_block",
				IsActive: true,
				Config: map[string]interface{}{
					"pii_types": []any{"SSN", "CREDIT_CARD"},
				},
			},
			piiTypes: []string{"EMAIL"},
			want:     nil,
		},
		// pii_warn
		{
			name: "pii_warn with PII present",
			rule: domain.PolicyRule{
				Name:     "warn-pii",
				RuleType: "pii_warn",
				IsActive: true,
				Config:   map[string]interface{}{},
			},
			piiTypes: []string{"EMAIL", "PHONE"},
			want:     &EvalResult{Action: ActionWarned, Reason: "PII detected: EMAIL, PHONE", Rule: "warn-pii"},
		},
		{
			name: "pii_warn no PII returns nil",
			rule: domain.PolicyRule{
				Name:     "warn-pii",
				RuleType: "pii_warn",
				IsActive: true,
				Config:   map[string]interface{}{},
			},
			piiTypes: []string{},
			want:     nil,
		},
		// keyword_block
		{
			name: "keyword_block text contains keyword",
			rule: domain.PolicyRule{
				Name:     "block-keywords",
				RuleType: "keyword_block",
				IsActive: true,
				Config: map[string]interface{}{
					"keywords": []any{"secret", "password"},
				},
			},
			text: "my secret project",
			want: &EvalResult{Action: ActionBlocked, Reason: "Blocked keyword: secret", Rule: "block-keywords"},
		},
		{
			name: "keyword_block case insensitive match",
			rule: domain.PolicyRule{
				Name:     "block-keywords",
				RuleType: "keyword_block",
				IsActive: true,
				Config: map[string]interface{}{
					"keywords": []any{"SECRET"},
				},
			},
			text: "My Secret Data",
			want: &EvalResult{Action: ActionBlocked, Reason: "Blocked keyword: SECRET", Rule: "block-keywords"},
		},
		{
			name: "keyword_block no match returns nil",
			rule: domain.PolicyRule{
				Name:     "block-keywords",
				RuleType: "keyword_block",
				IsActive: true,
				Config: map[string]interface{}{
					"keywords": []any{"secret", "password"},
				},
			},
			text: "just a normal message",
			want: nil,
		},
		// model_restrict
		{
			name: "model_restrict model in allowed list returns nil",
			rule: domain.PolicyRule{
				Name:     "restrict-models",
				RuleType: "model_restrict",
				IsActive: true,
				Config: map[string]interface{}{
					"allowed_models": []any{"gpt-4", "claude-3"},
				},
			},
			model: "gpt-4",
			want:  nil,
		},
		{
			name: "model_restrict model NOT in allowed list",
			rule: domain.PolicyRule{
				Name:     "restrict-models",
				RuleType: "model_restrict",
				IsActive: true,
				Config: map[string]interface{}{
					"allowed_models": []any{"gpt-4", "claude-3"},
				},
			},
			model: "llama-2",
			want:  &EvalResult{Action: ActionBlocked, Reason: "Model not allowed: llama-2", Rule: "restrict-models"},
		},
		{
			name: "model_restrict empty allowed list returns nil",
			rule: domain.PolicyRule{
				Name:     "restrict-models",
				RuleType: "model_restrict",
				IsActive: true,
				Config: map[string]interface{}{
					"allowed_models": []any{},
				},
			},
			model: "any-model",
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.evaluateRule(tt.rule, tt.text, tt.model, tt.piiTypes)

			if tt.want == nil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}

			if got == nil {
				t.Fatalf("expected %+v, got nil", tt.want)
			}
			if got.Action != tt.want.Action {
				t.Errorf("Action = %q, want %q", got.Action, tt.want.Action)
			}
			if got.Reason != tt.want.Reason {
				t.Errorf("Reason = %q, want %q", got.Reason, tt.want.Reason)
			}
			if got.Rule != tt.want.Rule {
				t.Errorf("Rule = %q, want %q", got.Rule, tt.want.Rule)
			}
		})
	}
}

func TestGetStringSlice(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]any
		key    string
		want   []string
	}{
		{
			name: "valid config returns string slice",
			config: map[string]any{
				"items": []any{"a", "b", "c"},
			},
			key:  "items",
			want: []string{"a", "b", "c"},
		},
		{
			name:   "missing key returns nil",
			config: map[string]any{},
			key:    "items",
			want:   nil,
		},
		{
			name: "wrong type returns nil",
			config: map[string]any{
				"items": "not-a-slice",
			},
			key:  "items",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getStringSlice(tt.config, tt.key)

			if tt.want == nil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}

			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d", len(got), len(tt.want))
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("index %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/shadowai/backend/internal/dlp"
)

func TestSanitizeChatRequestBody_RedactsSecret(t *testing.T) {
	svc := dlp.NewService("enforce")
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"my key is sk-1234567890abcdefghij1234567890abcdefghij please use it"}]}`)

	out := sanitizeChatRequestBody(body, svc)
	if strings.Contains(string(out), "sk-1234567890abcdefghij1234567890abcdefghij") {
		t.Errorf("secret not redacted in outbound body: %s", out)
	}

	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	messages := parsed["messages"].([]any)
	msg := messages[0].(map[string]any)
	content := msg["content"].(string)
	if !strings.Contains(content, "[redacted:") {
		t.Errorf("content should have redaction marker: %s", content)
	}
}

func TestSanitizeChatRequestBody_PreservesCleanBody(t *testing.T) {
	svc := dlp.NewService("enforce")
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"what is the weather?"}]}`)

	out := sanitizeChatRequestBody(body, svc)
	if string(out) != string(body) {
		t.Errorf("clean body should not be modified:\n  in:  %s\n  out: %s", body, out)
	}
}

func TestSanitizeChatRequestBody_NilService(t *testing.T) {
	body := []byte(`{"messages":[]}`)
	out := sanitizeChatRequestBody(body, nil)
	if string(out) != string(body) {
		t.Error("nil service should return body unchanged")
	}
}

func TestSanitizeChatRequestBody_InvalidJSON(t *testing.T) {
	svc := dlp.NewService("enforce")
	body := []byte(`not json`)
	out := sanitizeChatRequestBody(body, svc)
	if string(out) != string(body) {
		t.Error("invalid JSON should return body unchanged (fail-safe)")
	}
}

func TestApplyFlagCorrelation(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		flagged bool
		want    string
	}{
		{"allowed not flagged", "allowed", false, "allowed"},
		{"allowed flagged becomes warned", "allowed", true, "warned"},
		{"blocked flagged stays blocked", "blocked", true, "blocked"},
		{"warned flagged stays warned", "warned", true, "warned"},
		{"sanitized flagged stays sanitized", "sanitized", true, "sanitized"},
		{"sanitized not flagged stays sanitized", "sanitized", false, "sanitized"},
		{"blocked not flagged stays blocked", "blocked", false, "blocked"},
		{"unknown flagged becomes warned", "", true, "warned"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyFlagCorrelation(tt.action, tt.flagged)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

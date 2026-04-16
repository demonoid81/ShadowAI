package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/policy"
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

// TestPolicyActionFlow_FirewallFlagPlusDLPSanitize воспроизводит сценарий,
// из-за которого был заведён баг: firewall pipeline вернул ActionFlag
// (firewallFlagged=true), затем downstream h.dlpSvc.Evaluate вернул
// DLPActionSanitize. Скорректированный PolicyAction обязан быть "sanitized",
// а не "warned" — иначе факт реальной санитизации payload теряется в audit.
func TestPolicyActionFlow_FirewallFlagPlusDLPSanitize(t *testing.T) {
	h := &Handler{}

	// Шаг 1: merge policy (allowed) + DLP sanitize → "sanitized".
	merged := h.mergePolicyAction(string(policy.ActionAllowed), dlp.DLPActionSanitize)
	if merged != string(dlp.DLPActionSanitize) {
		t.Fatalf("mergePolicyAction(allowed, Sanitize) = %q, expected %q",
			merged, dlp.DLPActionSanitize)
	}

	// Шаг 2: корреляция с firewallFlagged=true не должна затирать sanitized.
	final := applyFlagCorrelation(merged, true)
	if final != string(dlp.DLPActionSanitize) {
		t.Errorf("applyFlagCorrelation(sanitized, flagged=true) = %q, expected %q — flag не должен понижать sanitized до warned",
			final, dlp.DLPActionSanitize)
	}

	// Обратный контроль: без флага результат также должен остаться sanitized.
	noFlag := applyFlagCorrelation(merged, false)
	if noFlag != string(dlp.DLPActionSanitize) {
		t.Errorf("applyFlagCorrelation(sanitized, flagged=false) = %q, expected %q",
			noFlag, dlp.DLPActionSanitize)
	}
}

// TestPolicyActionFlow_FirewallFlagOnly проверяет, что чистый flag без DLP
// санитизации действительно переводит allowed → warned (ожидаемое поведение).
func TestPolicyActionFlow_FirewallFlagOnly(t *testing.T) {
	h := &Handler{}
	merged := h.mergePolicyAction(string(policy.ActionAllowed), dlp.DLPActionAllow)
	if merged != string(policy.ActionAllowed) {
		t.Fatalf("mergePolicyAction(allowed, Allow) = %q, expected allowed", merged)
	}
	final := applyFlagCorrelation(merged, true)
	if final != string(policy.ActionWarned) {
		t.Errorf("applyFlagCorrelation(allowed, flagged=true) = %q, expected warned", final)
	}
}

// TestPolicyActionFlow_FirewallFlagPlusBlock проверяет, что block всегда
// побеждает flag — блокировка должна оставаться видимой в audit.
func TestPolicyActionFlow_FirewallFlagPlusBlock(t *testing.T) {
	h := &Handler{}
	merged := h.mergePolicyAction(string(policy.ActionBlocked), dlp.DLPActionAllow)
	if merged != string(policy.ActionBlocked) {
		t.Fatalf("mergePolicyAction(blocked, Allow) = %q, expected blocked", merged)
	}
	final := applyFlagCorrelation(merged, true)
	if final != string(policy.ActionBlocked) {
		t.Errorf("applyFlagCorrelation(blocked, flagged=true) = %q, expected blocked (flag не должен затирать block)", final)
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

package proxy

import (
	"strings"
	"testing"
)

// anthropicFrame строит один SSE frame с заданным event и JSON data.
// Используется в тестах вместо ручного конкатенирования с разными
// кавычками — так читать и писать проще.
func anthropicFrame(event, jsonData string) string {
	return "event: " + event + "\ndata: " + jsonData + "\n\n"
}

// TestParseAnthropicStreamUsage_CanonicalStream — типичный happy path:
// message_start с input_tokens, несколько content_block_delta, финальный
// message_delta с output_tokens, message_stop.
func TestParseAnthropicStreamUsage_CanonicalStream(t *testing.T) {
	body := []byte(
		anthropicFrame("message_start", `{"type":"message_start","message":{"model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":100,"output_tokens":0}}}`) +
			anthropicFrame("content_block_start", `{"type":"content_block_start","index":0}`) +
			anthropicFrame("content_block_delta", `{"type":"content_block_delta","delta":{"text":"Hello"}}`) +
			anthropicFrame("content_block_delta", `{"type":"content_block_delta","delta":{"text":" world"}}`) +
			anthropicFrame("content_block_stop", `{"type":"content_block_stop","index":0}`) +
			anthropicFrame("message_delta", `{"type":"message_delta","usage":{"output_tokens":42}}`) +
			anthropicFrame("message_stop", `{"type":"message_stop"}`),
	)

	u, err := parseAnthropicStreamUsage(body, "claude-3-5-sonnet-20241022")
	if err != nil {
		t.Fatal(err)
	}
	if !u.Found {
		t.Fatal("Found=false, want true")
	}
	if u.PromptTokens != 100 {
		t.Errorf("prompt = %d, want 100", u.PromptTokens)
	}
	if u.CompletionTokens != 42 {
		t.Errorf("completion = %d, want 42", u.CompletionTokens)
	}
	if u.TotalTokens != 142 {
		t.Errorf("total = %d, want 142 (input+output)", u.TotalTokens)
	}
	if u.Model != "claude-3-5-sonnet-20241022" {
		t.Errorf("model = %q, want claude-3-5-sonnet-20241022", u.Model)
	}
	// sonnet: {3e-6, 15e-6} → 100*3e-6 + 42*15e-6 = 9.3e-4
	const want = 9.3e-4
	if u.CostUSD < want*0.99 || u.CostUSD > want*1.01 {
		t.Errorf("cost = %g, want ~%g", u.CostUSD, want)
	}
}

// TestParseAnthropicStreamUsage_CumulativeOutputNotSummed — критичный
// тест: output_tokens в message_delta CUMULATIVE, не per-delta. Если
// провайдер шлёт несколько message_delta, берём ПОСЛЕДНЕЕ значение, а
// не сумму. Иначе overcounting в >1 message_delta случаях.
func TestParseAnthropicStreamUsage_CumulativeOutputNotSummed(t *testing.T) {
	body := []byte(
		anthropicFrame("message_start", `{"type":"message_start","message":{"usage":{"input_tokens":50}}}`) +
			anthropicFrame("message_delta", `{"type":"message_delta","usage":{"output_tokens":10}}`) +
			anthropicFrame("message_delta", `{"type":"message_delta","usage":{"output_tokens":25}}`) +
			anthropicFrame("message_delta", `{"type":"message_delta","usage":{"output_tokens":42}}`),
	)

	u, err := parseAnthropicStreamUsage(body, "claude-3-5-haiku-20241022")
	if err != nil {
		t.Fatal(err)
	}
	// Если суммировать: 10+25+42 = 77. Правильный ответ: last = 42.
	if u.CompletionTokens != 42 {
		t.Errorf("completion = %d, want 42 (cumulative — берём last, не сумму). "+
			"Если похоже на 77 — баг: значения суммируются", u.CompletionTokens)
	}
}

// TestParseAnthropicStreamUsage_InterruptedStream — stream прервался до
// финального message_stop. Должны взять last seen output_tokens.
func TestParseAnthropicStreamUsage_InterruptedStream(t *testing.T) {
	body := []byte(
		anthropicFrame("message_start", `{"type":"message_start","message":{"usage":{"input_tokens":50}}}`) +
			anthropicFrame("message_delta", `{"type":"message_delta","usage":{"output_tokens":15}}`),
		// connection dropped — message_stop не пришёл
	)

	u, err := parseAnthropicStreamUsage(body, "claude-3-haiku-20240307")
	if err != nil {
		t.Fatal(err)
	}
	if !u.Found {
		t.Error("Found=false для partial stream; want true (есть input+output)")
	}
	if u.PromptTokens != 50 || u.CompletionTokens != 15 {
		t.Errorf("partial usage = %d/%d, want 50/15", u.PromptTokens, u.CompletionTokens)
	}
}

// TestParseAnthropicStreamUsage_PingKeepaliveIgnored — ping-events от
// Anthropic не должны ломать парсинг или триггерить спуриозные updates.
func TestParseAnthropicStreamUsage_PingKeepaliveIgnored(t *testing.T) {
	body := []byte(
		anthropicFrame("ping", `{"type":"ping"}`) +
			anthropicFrame("message_start", `{"type":"message_start","message":{"usage":{"input_tokens":20}}}`) +
			anthropicFrame("ping", `{"type":"ping"}`) +
			anthropicFrame("message_delta", `{"type":"message_delta","usage":{"output_tokens":8}}`) +
			anthropicFrame("ping", `{"type":"ping"}`) +
			anthropicFrame("message_stop", `{"type":"message_stop"}`),
	)

	u, err := parseAnthropicStreamUsage(body, "claude-3-haiku-20240307")
	if err != nil {
		t.Fatal(err)
	}
	if u.PromptTokens != 20 || u.CompletionTokens != 8 {
		t.Errorf("ping должен игнорироваться; got %d/%d, want 20/8", u.PromptTokens, u.CompletionTokens)
	}
}

// TestParseAnthropicStreamUsage_NoUsageFoundFalse — empty/partial stream
// без usage-полей. Результат — Found=false без ошибки.
func TestParseAnthropicStreamUsage_NoUsageFoundFalse(t *testing.T) {
	body := []byte(
		anthropicFrame("ping", `{"type":"ping"}`) +
			anthropicFrame("content_block_delta", `{"type":"content_block_delta","delta":{"text":"hi"}}`),
	)

	u, err := parseAnthropicStreamUsage(body, "claude-3-haiku-20240307")
	if err != nil {
		t.Fatal(err)
	}
	if u.Found {
		t.Errorf("Found=true без usage данных; want false. got %+v", u)
	}
	if u.CostUSD != 0 {
		t.Errorf("cost = %g при Found=false; want 0", u.CostUSD)
	}
}

// TestParseAnthropicStreamUsage_MalformedJSONReturnsError — контракт
// StreamUsageProvider: invalid JSON в data → parser error, не soft-fail.
func TestParseAnthropicStreamUsage_MalformedJSONReturnsError(t *testing.T) {
	body := []byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usa\n\n") // truncated

	_, err := parseAnthropicStreamUsage(body, "claude-3-haiku-20240307")
	if err == nil {
		t.Error("malformed JSON должен вернуть parser error")
	}
	if err != nil && !strings.Contains(err.Error(), "anthropic") {
		t.Errorf("error должен содержать 'anthropic' namespace: %v", err)
	}
}

// TestParseAnthropicStreamUsage_ModelFallbackToRequest — если message_start
// не содержит model, fallback на requestModel для pricing.
func TestParseAnthropicStreamUsage_ModelFallbackToRequest(t *testing.T) {
	body := []byte(
		anthropicFrame("message_start", `{"type":"message_start","message":{"usage":{"input_tokens":100}}}`) +
			anthropicFrame("message_delta", `{"type":"message_delta","usage":{"output_tokens":50}}`),
	)

	u, err := parseAnthropicStreamUsage(body, "claude-3-opus-20240229")
	if err != nil {
		t.Fatal(err)
	}
	// opus: {15e-6, 75e-6} → 100*15e-6 + 50*75e-6 = 5.25e-3
	const want = 5.25e-3
	if u.CostUSD < want*0.99 || u.CostUSD > want*1.01 {
		t.Errorf("cost = %g, want ~%g (opus pricing по requestModel)", u.CostUSD, want)
	}
}

// TestParseAnthropicStreamUsage_OnlyInput — только message_start без
// message_delta (ответ пустой, но usage.input_tokens всё равно известен).
// Found=true, completion=0, cost по pricing table.
func TestParseAnthropicStreamUsage_OnlyInput(t *testing.T) {
	body := []byte(
		anthropicFrame("message_start", `{"type":"message_start","message":{"model":"claude-3-haiku-20240307","usage":{"input_tokens":15}}}`) +
			anthropicFrame("message_stop", `{"type":"message_stop"}`),
	)

	u, err := parseAnthropicStreamUsage(body, "claude-3-haiku-20240307")
	if err != nil {
		t.Fatal(err)
	}
	if !u.Found {
		t.Fatal("Found=false; want true (input_tokens > 0)")
	}
	if u.PromptTokens != 15 || u.CompletionTokens != 0 {
		t.Errorf("usage = %d/%d, want 15/0", u.PromptTokens, u.CompletionTokens)
	}
	// haiku: {0.25e-6, 1.25e-6} → 15*0.25e-6 + 0 = 3.75e-6
	const want = 3.75e-6
	if u.CostUSD < want*0.99 || u.CostUSD > want*1.01 {
		t.Errorf("cost = %g, want ~%g", u.CostUSD, want)
	}
}

// TestParseAnthropicStreamUsage_EmptyBody — sanity check.
func TestParseAnthropicStreamUsage_EmptyBody(t *testing.T) {
	u, err := parseAnthropicStreamUsage(nil, "model")
	if err != nil {
		t.Errorf("err = %v для пустого body", err)
	}
	if u.Found {
		t.Error("Found=true для пустого body")
	}
}

// TestAnthropicProvider_StreamUsageDelegation — integration: через
// интерфейс StreamUsageProvider.
func TestAnthropicProvider_StreamUsageDelegation(t *testing.T) {
	p := NewAnthropicProvider("test-key")
	body := []byte(
		anthropicFrame("message_start", `{"type":"message_start","message":{"model":"claude-3-5-haiku-20241022","usage":{"input_tokens":10}}}`) +
			anthropicFrame("message_delta", `{"type":"message_delta","usage":{"output_tokens":5}}`),
	)

	u, err := p.ParseStreamUsage(body, "claude-3-5-haiku-20241022")
	if err != nil {
		t.Fatal(err)
	}
	if !u.Found {
		t.Error("Anthropic.ParseStreamUsage should return Found=true")
	}
	if u.PromptTokens != 10 || u.CompletionTokens != 5 {
		t.Errorf("tokens = %d/%d, want 10/5", u.PromptTokens, u.CompletionTokens)
	}
	// Verify Anthropic реализует StreamUsageProvider.
	var _ StreamUsageProvider = p
}

// TestParseAnthropicStreamUsage_UnknownEventIgnored — forward-compat:
// новые event types не ломают парсер.
func TestParseAnthropicStreamUsage_UnknownEventIgnored(t *testing.T) {
	body := []byte(
		anthropicFrame("message_start", `{"type":"message_start","message":{"usage":{"input_tokens":5}}}`) +
			anthropicFrame("some_future_event", `{"type":"some_future_event","data":{"weird":true}}`) +
			anthropicFrame("message_delta", `{"type":"message_delta","usage":{"output_tokens":3}}`),
	)

	u, err := parseAnthropicStreamUsage(body, "claude-3-haiku-20240307")
	if err != nil {
		t.Fatal(err)
	}
	if u.PromptTokens != 5 || u.CompletionTokens != 3 {
		t.Errorf("unknown event должен игнорироваться, got %d/%d", u.PromptTokens, u.CompletionTokens)
	}
}

// TestParseAnthropicStreamUsage_Partial_InterruptedBeforeMessageStop — PR-F7.4:
// message_delta received (output_tokens known) but message_stop absent.
// Partial=true expected — stream was interrupted mid-flight.
func TestParseAnthropicStreamUsage_Partial_InterruptedBeforeMessageStop(t *testing.T) {
	body := []byte(
		anthropicFrame("message_start", `{"type":"message_start","message":{"model":"claude-3-5-sonnet","usage":{"input_tokens":50,"output_tokens":0}}}`) +
			anthropicFrame("content_block_delta", `{"type":"content_block_delta","delta":{"text":"Partial"}}`) +
			anthropicFrame("message_delta", `{"type":"message_delta","usage":{"output_tokens":10}}`))
	// No message_stop.

	usage, err := parseAnthropicStreamUsage(body, "claude-3-5-sonnet")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !usage.Found {
		t.Fatal("expected Found=true")
	}
	if !usage.Partial {
		t.Error("Partial=false; expected true (no message_stop in stream)")
	}
	if usage.PromptTokens != 50 || usage.CompletionTokens != 10 {
		t.Errorf("tokens: prompt=%d completion=%d, want 50/10", usage.PromptTokens, usage.CompletionTokens)
	}
}

// TestParseAnthropicStreamUsage_NotPartial_WhenMessageStopSeen — PR-F7.4:
// complete stream with message_stop → Partial=false (final usage).
func TestParseAnthropicStreamUsage_NotPartial_WhenMessageStopSeen(t *testing.T) {
	body := []byte(
		anthropicFrame("message_start", `{"type":"message_start","message":{"model":"claude-3-5-sonnet","usage":{"input_tokens":50,"output_tokens":0}}}`) +
			anthropicFrame("message_delta", `{"type":"message_delta","usage":{"output_tokens":10}}`) +
			anthropicFrame("message_stop", `{"type":"message_stop"}`))

	usage, err := parseAnthropicStreamUsage(body, "claude-3-5-sonnet")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !usage.Found {
		t.Fatal("expected Found=true")
	}
	if usage.Partial {
		t.Error("Partial=true; expected false (message_stop was received → final)")
	}
}

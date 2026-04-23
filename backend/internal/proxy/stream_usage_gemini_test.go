package proxy

import (
	"strings"
	"testing"
)

// geminiFrame собирает один data-only SSE frame для Gemini.
func geminiFrame(jsonData string) string {
	return "data: " + jsonData + "\n\n"
}

// TestParseGeminiStreamUsage_FinalFrameHasUsage — канонический случай:
// несколько промежуточных chunks с content, финальный — с usageMetadata.
func TestParseGeminiStreamUsage_FinalFrameHasUsage(t *testing.T) {
	body := []byte(
		geminiFrame(`{"candidates":[{"content":{"parts":[{"text":"Hello"}]}}],"modelVersion":"gemini-1.5-flash"}`) +
			geminiFrame(`{"candidates":[{"content":{"parts":[{"text":" world"}]}}],"modelVersion":"gemini-1.5-flash"}`) +
			geminiFrame(`{"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2,"totalTokenCount":12},"modelVersion":"gemini-1.5-flash"}`),
	)

	u, err := parseGeminiStreamUsage(body, "gemini-1.5-flash")
	if err != nil {
		t.Fatal(err)
	}
	if !u.Found {
		t.Fatal("Found=false, want true")
	}
	if u.PromptTokens != 10 || u.CompletionTokens != 2 || u.TotalTokens != 12 {
		t.Errorf("tokens = %d/%d/%d, want 10/2/12", u.PromptTokens, u.CompletionTokens, u.TotalTokens)
	}
	if u.Model != "gemini-1.5-flash" {
		t.Errorf("model = %q, want gemini-1.5-flash", u.Model)
	}
	// flash: {0.075e-6, 0.30e-6} → 10*0.075e-6 + 2*0.30e-6 = 1.35e-6
	const want = 1.35e-6
	if u.CostUSD < want*0.99 || u.CostUSD > want*1.01 {
		t.Errorf("cost = %g, want ~%g", u.CostUSD, want)
	}
}

// TestParseGeminiStreamUsage_IntermediateFrameHasUsage — docs не фиксируют
// позицию usage chunk'а. Если usage пришёл в ПРОМЕЖУТОЧНОМ frame, а
// финальный его не содержит — должны взять промежуточный.
func TestParseGeminiStreamUsage_IntermediateFrameHasUsage(t *testing.T) {
	body := []byte(
		geminiFrame(`{"candidates":[{"content":{"parts":[{"text":"hi"}]}}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":1,"totalTokenCount":6}}`) +
			geminiFrame(`{"candidates":[{"finishReason":"STOP"}]}`),
	)

	u, err := parseGeminiStreamUsage(body, "gemini-1.5-flash")
	if err != nil {
		t.Fatal(err)
	}
	if !u.Found {
		t.Fatal("Found=false, want true (usage был в промежуточном frame)")
	}
	if u.PromptTokens != 5 || u.CompletionTokens != 1 {
		t.Errorf("tokens = %d/%d, want 5/1", u.PromptTokens, u.CompletionTokens)
	}
}

// TestParseGeminiStreamUsage_LastNonEmptyWins — если несколько chunks
// содержат usage, берём последний. Но пустой usageMetadata:{} НЕ должен
// перекрывать предыдущий non-empty (иначе потеряем данные).
func TestParseGeminiStreamUsage_LastNonEmptyWins(t *testing.T) {
	body := []byte(
		geminiFrame(`{"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":1,"totalTokenCount":6}}`) +
			// Пустой usageMetadata — проверка что мы его НЕ берём
			geminiFrame(`{"usageMetadata":{}}`) +
			geminiFrame(`{"usageMetadata":{"promptTokenCount":20,"candidatesTokenCount":10,"totalTokenCount":30}}`),
	)

	u, err := parseGeminiStreamUsage(body, "gemini-1.5-flash")
	if err != nil {
		t.Fatal(err)
	}
	// Ответ: берём последний non-empty (20/10/30), не пустой {}, не первый 5/1/6.
	if u.PromptTokens != 20 || u.CompletionTokens != 10 || u.TotalTokens != 30 {
		t.Errorf("tokens = %d/%d/%d, want 20/10/30 (last non-empty wins)",
			u.PromptTokens, u.CompletionTokens, u.TotalTokens)
	}
}

// TestParseGeminiStreamUsage_EmptyUsageNotOverwrites — regression guard:
// если первый chunk имеет non-empty usage, а последующие шлют пустой
// usageMetadata:{}, финальный результат должен быть первый non-empty,
// а не reset.
func TestParseGeminiStreamUsage_EmptyUsageNotOverwrites(t *testing.T) {
	body := []byte(
		geminiFrame(`{"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":50,"totalTokenCount":150}}`) +
			geminiFrame(`{"usageMetadata":{}}`) +
			geminiFrame(`{"usageMetadata":{}}`),
	)

	u, err := parseGeminiStreamUsage(body, "gemini-1.5-flash")
	if err != nil {
		t.Fatal(err)
	}
	if u.PromptTokens != 100 || u.CompletionTokens != 50 {
		t.Errorf("tokens = %d/%d, want 100/50 (non-empty не должен перезаписываться пустым)",
			u.PromptTokens, u.CompletionTokens)
	}
}

// TestParseGeminiStreamUsage_NoUsageFoundFalse — stream без usage.
func TestParseGeminiStreamUsage_NoUsageFoundFalse(t *testing.T) {
	body := []byte(
		geminiFrame(`{"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}`) +
			geminiFrame(`{"candidates":[{"finishReason":"STOP"}]}`),
	)

	u, err := parseGeminiStreamUsage(body, "gemini-1.5-flash")
	if err != nil {
		t.Fatal(err)
	}
	if u.Found {
		t.Errorf("Found=true без usage данных; want false. got %+v", u)
	}
}

// TestParseGeminiStreamUsage_MalformedJSONReturnsError — контракт
// StreamUsageProvider: malformed JSON → parser error.
func TestParseGeminiStreamUsage_MalformedJSONReturnsError(t *testing.T) {
	body := []byte("data: {\"usageMetadata\":{\"promptTokenCount\":\n\n") // truncated

	_, err := parseGeminiStreamUsage(body, "gemini-1.5-flash")
	if err == nil {
		t.Error("malformed JSON должен вернуть parser error")
	}
	if err != nil && !strings.Contains(err.Error(), "gemini") {
		t.Errorf("error должен содержать 'gemini' namespace: %v", err)
	}
}

// TestParseGeminiStreamUsage_TotalTokenCountFallback — если provider
// не вернул totalTokenCount, считаем как prompt+completion.
func TestParseGeminiStreamUsage_TotalTokenCountFallback(t *testing.T) {
	body := []byte(
		geminiFrame(`{"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5}}`),
	)

	u, err := parseGeminiStreamUsage(body, "gemini-1.5-flash")
	if err != nil {
		t.Fatal(err)
	}
	if u.TotalTokens != 15 {
		t.Errorf("total = %d, want 15 (fallback = prompt+completion)", u.TotalTokens)
	}
}

// TestParseGeminiStreamUsage_ModelFallbackToRequest — если chunks без
// modelVersion, fallback на requestModel для pricing.
func TestParseGeminiStreamUsage_ModelFallbackToRequest(t *testing.T) {
	body := []byte(
		geminiFrame(`{"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":50,"totalTokenCount":150}}`),
	)

	u, err := parseGeminiStreamUsage(body, "gemini-1.5-pro")
	if err != nil {
		t.Fatal(err)
	}
	// pro: {3.5e-6, 10.5e-6} → 100*3.5e-6 + 50*10.5e-6 = 8.75e-4
	const want = 8.75e-4
	if u.CostUSD < want*0.99 || u.CostUSD > want*1.01 {
		t.Errorf("cost = %g, want ~%g (pro pricing по requestModel)", u.CostUSD, want)
	}
}

// TestParseGeminiStreamUsage_EmptyBody — sanity check.
func TestParseGeminiStreamUsage_EmptyBody(t *testing.T) {
	u, err := parseGeminiStreamUsage(nil, "model")
	if err != nil {
		t.Errorf("err = %v для пустого body", err)
	}
	if u.Found {
		t.Error("Found=true для пустого body")
	}
}

// TestGeminiProvider_StreamUsageDelegation — integration через interface.
func TestGeminiProvider_StreamUsageDelegation(t *testing.T) {
	p := NewGeminiProvider("test-key")
	body := []byte(
		geminiFrame(`{"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15},"modelVersion":"gemini-1.5-flash"}`),
	)

	u, err := p.ParseStreamUsage(body, "gemini-1.5-flash")
	if err != nil {
		t.Fatal(err)
	}
	if !u.Found {
		t.Error("GeminiProvider.ParseStreamUsage must return Found=true")
	}
	// Verify compile-time interface compliance.
	var _ StreamUsageProvider = p
}

// TestParseGeminiStreamUsage_DONESkipped — Gemini НЕ использует
// data: [DONE] sentinel (это OpenAI specific). Но если вдруг встретится
// (через reverse-proxy), json.Unmarshal на "[DONE]" упадёт и мы
// корректно вернём parser error.
func TestParseGeminiStreamUsage_NonJSONSentinel(t *testing.T) {
	// Gemini протокол не содержит [DONE], но если по какой-то причине
	// кто-то добавит в proxy chain — это будет malformed JSON для нас.
	body := []byte(
		geminiFrame(`{"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":1}}`) +
			geminiFrame(`[DONE]`), // не JSON
	)

	_, err := parseGeminiStreamUsage(body, "gemini-1.5-flash")
	if err == nil {
		t.Error("non-JSON frame должен вернуть parser error (Gemini не использует [DONE])")
	}
}

// TestParseGeminiStreamUsage_Partial_InterruptedBeforeFinishReason — PR-F7.4:
// usageMetadata extracted but no candidate has finishReason → Partial=true.
func TestParseGeminiStreamUsage_Partial_InterruptedBeforeFinishReason(t *testing.T) {
	body := []byte(
		`data: {"candidates":[{"content":{"parts":[{"text":"Partial"}]}}],"modelVersion":"gemini-1.5-pro","usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}` + "\n\n")
	// No finishReason in any candidate.

	usage, err := parseGeminiStreamUsage(body, "gemini-1.5-pro")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !usage.Found {
		t.Fatal("expected Found=true")
	}
	if !usage.Partial {
		t.Error("Partial=false; expected true (no finishReason in stream)")
	}
	if usage.TotalTokens != 15 {
		t.Errorf("TotalTokens=%d, want 15", usage.TotalTokens)
	}
}

// TestParseGeminiStreamUsage_NotPartial_WhenFinishReasonSeen — PR-F7.4:
// finishReason present → Partial=false.
func TestParseGeminiStreamUsage_NotPartial_WhenFinishReasonSeen(t *testing.T) {
	body := []byte(
		`data: {"candidates":[{"content":{"parts":[{"text":"Done"}],"role":"model"},"finishReason":"STOP"}],"modelVersion":"gemini-1.5-pro","usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}` + "\n\n")

	usage, err := parseGeminiStreamUsage(body, "gemini-1.5-pro")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !usage.Found {
		t.Fatal("expected Found=true")
	}
	if usage.Partial {
		t.Error("Partial=true; expected false (finishReason=STOP present)")
	}
}

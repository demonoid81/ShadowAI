package streaming

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestAdapterForProvider_KnownNames — factory покрывает все
// SupportedProviders().
func TestAdapterForProvider_KnownNames(t *testing.T) {
	for _, name := range SupportedProviders() {
		a, ok := AdapterForProvider(name)
		if !ok {
			t.Errorf("AdapterForProvider(%q) → false, want known", name)
			continue
		}
		if a.Decoder == nil || a.Emitter == nil {
			t.Errorf("adapter для %q: Decoder=%v Emitter=%v", name, a.Decoder, a.Emitter)
		}
	}
}

// TestAdapterForProvider_Unknown — unsupported provider → false +
// пустой Adapter. Caller должен fallback'ить на buffered path.
func TestAdapterForProvider_Unknown(t *testing.T) {
	cases := []string{"", "cohere", "unknown-xyz", "OPENAI" /* case-sensitive */}
	for _, name := range cases {
		if _, ok := AdapterForProvider(name); ok {
			t.Errorf("AdapterForProvider(%q) → true, want false", name)
		}
	}
}

// TestOpenAICompatEmitter_EmitError_Format — terminal error frame
// имеет event: error + valid JSON payload с code+message.
func TestOpenAICompatEmitter_EmitError_Format(t *testing.T) {
	var buf bytes.Buffer
	em := OpenAICompatEmitter{}
	if err := em.EmitError(context.Background(), &buf, "blocked", "content blocked by firewall"); err != nil {
		t.Fatalf("EmitError: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "event: error\n") {
		t.Errorf("missing event: error prefix; got: %q", out)
	}
	if !strings.HasSuffix(out, "\n\n") {
		t.Errorf("missing SSE frame terminator \\n\\n; got: %q", out)
	}
	// Распарсим data payload.
	idx := strings.Index(out, "data: ")
	if idx < 0 {
		t.Fatalf("no data: line; got: %q", out)
	}
	dataLine := out[idx+len("data: ") : len(out)-len("\n\n")]
	var payload map[string]string
	if err := json.Unmarshal([]byte(dataLine), &payload); err != nil {
		t.Fatalf("data payload is not valid JSON: %v (payload: %q)", err, dataLine)
	}
	if payload["code"] != "blocked" || payload["message"] != "content blocked by firewall" {
		t.Errorf("payload mismatch: %+v", payload)
	}
}

// TestAnthropicEmitter_EmitError_Shape — Anthropic-specific error
// envelope {"type":"error","error":{"type":code,"message":msg}}.
func TestAnthropicEmitter_EmitError_Shape(t *testing.T) {
	var buf bytes.Buffer
	em := AnthropicEmitter{}
	if err := em.EmitError(context.Background(), &buf, "overloaded_error", "retry later"); err != nil {
		t.Fatalf("EmitError: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "event: error\n") {
		t.Errorf("missing event: error prefix")
	}
	idx := strings.Index(out, "data: ")
	if idx < 0 {
		t.Fatalf("no data: line")
	}
	dataLine := out[idx+len("data: ") : len(out)-len("\n\n")]
	var payload struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(dataLine), &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if payload.Type != "error" || payload.Error.Type != "overloaded_error" || payload.Error.Message != "retry later" {
		t.Errorf("shape mismatch: %+v", payload)
	}
}

// TestGeminiEmitter_EmitError_DataOnly — Gemini не использует
// event: поле, только data: {...}\n\n.
func TestGeminiEmitter_EmitError_DataOnly(t *testing.T) {
	var buf bytes.Buffer
	em := GeminiEmitter{}
	if err := em.EmitError(context.Background(), &buf, "INTERNAL", "upstream failed"); err != nil {
		t.Fatalf("EmitError: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "event:") {
		t.Errorf("Gemini не должен использовать event: field; got: %q", out)
	}
	if !strings.HasPrefix(out, "data: ") || !strings.HasSuffix(out, "\n\n") {
		t.Errorf("invalid SSE frame: %q", out)
	}
}

// TestOllamaEmitter_EmitError_NDJSON — одна строка JSON с error +
// done=true + trailing \n.
func TestOllamaEmitter_EmitError_NDJSON(t *testing.T) {
	var buf bytes.Buffer
	em := OllamaEmitter{}
	if err := em.EmitError(context.Background(), &buf, "blocked", "firewall"); err != nil {
		t.Fatalf("EmitError: %v", err)
	}
	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("missing \\n terminator; got: %q", out)
	}
	// Одна строка JSON.
	line := strings.TrimRight(out, "\n")
	var payload struct {
		Error string `json:"error"`
		Code  string `json:"code"`
		Done  bool   `json:"done"`
	}
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("invalid NDJSON: %v", err)
	}
	if payload.Error != "firewall" || payload.Code != "blocked" || !payload.Done {
		t.Errorf("shape mismatch: %+v", payload)
	}
}

// TestEmitter_RejectsEmptyRawBytes — F7.1 invariant: Emit без
// RawBytes возвращает error. sanitize active usage — F7.2, здесь
// явно запрещено, чтобы не эмитить bytes которых не было.
func TestEmitter_RejectsEmptyRawBytes(t *testing.T) {
	ctx := context.Background()
	ev := Event{Type: EventDeltaText, Text: "hello"} // без RawBytes
	cases := []Emitter{
		OpenAICompatEmitter{},
		AnthropicEmitter{},
		GeminiEmitter{},
		OllamaEmitter{},
	}
	for _, em := range cases {
		var buf bytes.Buffer
		if err := em.Emit(ctx, &buf, ev); err == nil {
			t.Errorf("%T.Emit(empty RawBytes) returned nil, want error", em)
		}
	}
}

// TestOpenAICompat_UsageFrame_Semantics — frame с usage и пустым
// choices → EventUsageUpdate с правильными токенами.
func TestOpenAICompat_UsageFrame_Semantics(t *testing.T) {
	a, _ := AdapterForProvider("openai")
	var events []Event
	_ = a.Decoder.Decode(context.Background(), bytes.NewReader(fixtureOpenAIWithUsage), func(ev Event) error {
		events = append(events, ev)
		return nil
	})
	var usageEv *Event
	for i := range events {
		if events[i].Type == EventUsageUpdate {
			usageEv = &events[i]
			break
		}
	}
	if usageEv == nil {
		t.Fatal("no usage_update event")
	}
	if usageEv.Usage == nil {
		t.Fatal("usage_update без Usage поля")
	}
	if usageEv.Usage.PromptTokens != 5 || usageEv.Usage.CompletionTokens != 1 || usageEv.Usage.TotalTokens != 6 {
		t.Errorf("usage = %+v, want P=5 C=1 T=6", usageEv.Usage)
	}
}

// TestAnthropic_ProviderError_Mapping — event: error с
// {"error":{"type":...,"message":...}} → EventProviderError с
// populated ProviderErr.
func TestAnthropic_ProviderError_Mapping(t *testing.T) {
	in := []byte(
		`event: error` + "\n" +
			`data: {"type":"error","error":{"type":"overloaded_error","message":"try later"}}` + "\n\n")
	a, _ := AdapterForProvider("anthropic")
	var events []Event
	_ = a.Decoder.Decode(context.Background(), bytes.NewReader(in), func(ev Event) error {
		events = append(events, ev)
		return nil
	})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Type != EventProviderError {
		t.Errorf("type = %q, want provider_error", ev.Type)
	}
	if ev.ProviderErr == nil {
		t.Fatal("ProviderErr nil")
	}
	if ev.ProviderErr.Code != "overloaded_error" || ev.ProviderErr.Message != "try later" {
		t.Errorf("ProviderErr = %+v", ev.ProviderErr)
	}
}

// TestOllama_ErrorLine_Mapping — Ollama error line.
func TestOllama_ErrorLine_Mapping(t *testing.T) {
	in := []byte(`{"error":"model not found"}` + "\n")
	a, _ := AdapterForProvider("ollama")
	var events []Event
	_ = a.Decoder.Decode(context.Background(), bytes.NewReader(in), func(ev Event) error {
		events = append(events, ev)
		return nil
	})
	if len(events) != 1 || events[0].Type != EventProviderError {
		t.Fatalf("events = %+v", events)
	}
	if events[0].ProviderErr == nil || events[0].ProviderErr.Message != "model not found" {
		t.Errorf("ProviderErr = %+v", events[0].ProviderErr)
	}
}

package streaming

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestRoundTrip_BytesIdentity — ядро F7.1 (RFC §8.6 acceptance
// criteria §20 / decisions §21). Для каждого canonical fixture:
//
//	decode(X) → emit каждого Event в порядке → получаем X (byte-identical).
//
// Это regression guard для identity-preservation на allow path.
// Любое изменение adapter'а, которое нарушит identity (re-encoding
// на Emit, пропуск unknown frame'а, mutation RawBytes), упадёт здесь.
func TestRoundTrip_BytesIdentity(t *testing.T) {
	cases := []struct {
		name    string
		adapter Adapter
		input   []byte
	}{
		{
			name:    "openai_normal",
			adapter: mustAdapter(t, "openai"),
			input:   fixtureOpenAINormal,
		},
		{
			name:    "openai_with_usage",
			adapter: mustAdapter(t, "openai"),
			input:   fixtureOpenAIWithUsage,
		},
		{
			name:    "openai_malformed",
			adapter: mustAdapter(t, "openai"),
			input:   fixtureOpenAIMalformed,
		},
		{
			name:    "openrouter_keepalive",
			adapter: mustAdapter(t, "openrouter"),
			input:   fixtureOpenRouterKeepalive,
		},
		{
			name:    "groq_like_openai",
			adapter: mustAdapter(t, "groq"),
			input:   fixtureOpenAINormal,
		},
		{
			name:    "mistral_like_openai",
			adapter: mustAdapter(t, "mistral"),
			input:   fixtureOpenAINormal,
		},
		{
			name:    "anthropic_named",
			adapter: mustAdapter(t, "anthropic"),
			input:   fixtureAnthropicNamed,
		},
		{
			name:    "gemini_sse",
			adapter: mustAdapter(t, "gemini"),
			input:   fixtureGeminiSSE,
		},
		{
			name:    "ollama_ndjson",
			adapter: mustAdapter(t, "ollama"),
			input:   fixtureOllamaNDJSON,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, events, err := roundTrip(c.adapter, c.input)
			if err != nil {
				t.Fatalf("roundTrip err: %v", err)
			}
			if !bytes.Equal(got, c.input) {
				t.Errorf("identity mismatch.\nwant (%d bytes):\n%q\n\ngot (%d bytes):\n%q",
					len(c.input), c.input, len(got), got)
			}
			if len(events) == 0 {
				t.Error("zero events emitted for non-empty stream")
			}
			// Sanity: каждый event должен иметь non-empty RawBytes —
			// это инвариант F7.1 (§8.6 identity). Единственное
			// исключение — hypothetical sanitize event без Raw (F7.2).
			for i, ev := range events {
				if len(ev.RawBytes) == 0 {
					t.Errorf("event[%d] type=%s has empty RawBytes — F7.1 invariant violated", i, ev.Type)
				}
			}
		})
	}
}

// TestRoundTrip_EventTypeCoverage — проверяет, что на canonical
// fixtures emitятся все основные EventType'ы (кроме ProviderError —
// он проверяется в отдельных adapter тестах).
func TestRoundTrip_EventTypeCoverage(t *testing.T) {
	a := mustAdapter(t, "anthropic")
	_, events, err := roundTrip(a, fixtureAnthropicNamed)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	seen := map[EventType]int{}
	for _, ev := range events {
		seen[ev.Type]++
	}
	// Ожидаем: minimum message_delta → usage_update, message_stop,
	// content_block_delta → delta_text, ping → unknown_chunk.
	if seen[EventDeltaText] == 0 {
		t.Error("no delta_text events")
	}
	if seen[EventUsageUpdate] == 0 {
		t.Error("no usage_update events")
	}
	if seen[EventMessageStop] == 0 {
		t.Error("no message_stop events")
	}
	if seen[EventUnknownChunk] == 0 {
		t.Error("expected ping to produce unknown_chunk event")
	}
}

// TestRoundTrip_OpenAI_DoneSentinel — [DONE] должен стать
// EventMessageStop.
func TestRoundTrip_OpenAI_DoneSentinel(t *testing.T) {
	a := mustAdapter(t, "openai")
	_, events, err := roundTrip(a, fixtureOpenAINormal)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	hasStop := false
	for _, ev := range events {
		if ev.Type == EventMessageStop {
			hasStop = true
		}
	}
	if !hasStop {
		t.Error("[DONE] sentinel не был классифицирован как message_stop")
	}
}

// TestRoundTrip_Ollama_DoneFrame — done=true должен дать usage_update
// с Meta.done="true".
func TestRoundTrip_Ollama_DoneFrame(t *testing.T) {
	a := mustAdapter(t, "ollama")
	_, events, err := roundTrip(a, fixtureOllamaNDJSON)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	var lastUsage *Event
	for i := range events {
		if events[i].Type == EventUsageUpdate {
			lastUsage = &events[i]
		}
	}
	if lastUsage == nil {
		t.Fatal("no usage_update event from done=true frame")
	}
	if lastUsage.Meta["done"] != "true" {
		t.Errorf("Meta.done = %q, want \"true\"", lastUsage.Meta["done"])
	}
	if lastUsage.Usage == nil || lastUsage.Usage.CompletionTokens != 2 {
		t.Errorf("usage unexpected: %+v", lastUsage.Usage)
	}
}

// TestRoundTrip_Gemini_UsageInFinalFrame.
func TestRoundTrip_Gemini_UsageInFinalFrame(t *testing.T) {
	a := mustAdapter(t, "gemini")
	_, events, err := roundTrip(a, fixtureGeminiSSE)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Финальный event (или near-final): usage_update с
	// TotalTokenCount=5.
	var usageSeen bool
	for _, ev := range events {
		if ev.Type == EventUsageUpdate && ev.Usage != nil && ev.Usage.TotalTokens == 5 {
			usageSeen = true
		}
	}
	if !usageSeen {
		t.Error("usage_update с TotalTokens=5 не найден")
	}
}

func TestRoundTrip_Gemini_TextWithUsage_ClassifiedAsDeltaText(t *testing.T) {
	input := []byte(`data: {"candidates":[{"content":{"parts":[{"text":"email user@example.com"}],"role":"model"}}],"modelVersion":"gemini-1.5-pro","usageMetadata":{"promptTokenCount":4,"candidatesTokenCount":1,"totalTokenCount":5}}` + "\n\n")
	adapter := mustAdapter(t, "gemini")
	_, events, err := roundTrip(adapter, input)
	if err != nil {
		t.Fatalf("roundTrip: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1: %+v", len(events), events)
	}
	if events[0].Type != EventDeltaText {
		t.Fatalf("Gemini text+usage Type = %s, want %s", events[0].Type, EventDeltaText)
	}
	if events[0].Text != "email user@example.com" {
		t.Fatalf("Gemini text+usage Text = %q", events[0].Text)
	}
	if events[0].Usage == nil || events[0].Usage.TotalTokens != 5 {
		t.Fatalf("Gemini text+usage must retain usage metadata, got %+v", events[0].Usage)
	}
}

// TestRoundTrip_Malformed_EmitsUnknownChunk.
func TestRoundTrip_Malformed_EmitsUnknownChunk(t *testing.T) {
	a := mustAdapter(t, "openai")
	_, events, err := roundTrip(a, fixtureOpenAIMalformed)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	hasUnknown := false
	for _, ev := range events {
		if ev.Type == EventUnknownChunk {
			hasUnknown = true
		}
	}
	if !hasUnknown {
		t.Error("malformed frame не превратился в unknown_chunk")
	}
	// И round-trip identity всё равно должен сохраниться — это
	// проверяется в TestRoundTrip_BytesIdentity.
}

// ---------------------------------------------------------------------------
// PR-F7.5: EmitSanitized tests
// ---------------------------------------------------------------------------

// TestEmitSanitized_OpenAI_DeltaText_ReplacesContent — основной тест F7.5.
// Входной SSE delta frame с исходным текстом; EmitSanitized должен выдать
// валидный SSE frame с заменённым content, сохранив все прочие поля.
func TestEmitSanitized_OpenAI_DeltaText_ReplacesContent(t *testing.T) {
	original := []byte(`data: {"id":"c-1","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"call user@example.com"},"finish_reason":null}]}` + "\n\n")
	sanitized := "[redacted:email]"

	// Decode to get the Event.
	adapter := mustAdapter(t, "openai")
	var events []Event
	if err := adapter.Decoder.Decode(context.Background(), bytes.NewReader(original), func(ev Event) error {
		events = append(events, ev)
		return nil
	}); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(events) != 1 || events[0].Type != EventDeltaText {
		t.Fatalf("expected 1 delta_text event, got %+v", events)
	}

	var out bytes.Buffer
	if err := adapter.Emitter.EmitSanitized(context.Background(), &out, events[0], sanitized); err != nil {
		t.Fatalf("EmitSanitized: %v", err)
	}

	output := out.String()
	// Must be valid SSE frame.
	if !strings.HasPrefix(output, "data: ") {
		t.Errorf("output not SSE frame: %q", output)
	}
	if !strings.HasSuffix(output, "\n\n") {
		t.Errorf("output missing \\n\\n terminator: %q", output)
	}
	// Must contain sanitized text, not original.
	if !strings.Contains(output, sanitized) {
		t.Errorf("output does not contain sanitized text %q: %s", sanitized, output)
	}
	if strings.Contains(output, "user@example.com") {
		t.Errorf("output still contains original PII: %s", output)
	}
	// Non-text fields must be preserved.
	if !strings.Contains(output, `"id":"c-1"`) {
		t.Errorf("output lost id field: %s", output)
	}
	if !strings.Contains(output, `"model":"gpt-4o"`) {
		t.Errorf("output lost model field: %s", output)
	}
	t.Logf("EmitSanitized/openai: %s", output)
}

// TestEmitSanitized_OpenAI_UsageFrame_Identity — non-delta_text events
// (usage, stop, unknown) must be emitted identity. Safety invariant:
// usage/stop frames must NOT be modified even during a sanitize pass.
func TestEmitSanitized_OpenAI_UsageFrame_Identity(t *testing.T) {
	usageFrame := []byte(`data: {"id":"c-2","model":"gpt-4o","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}` + "\n\n")

	adapter := mustAdapter(t, "openai")
	var events []Event
	adapter.Decoder.Decode(context.Background(), bytes.NewReader(usageFrame), func(ev Event) error { //nolint:errcheck
		events = append(events, ev)
		return nil
	})
	if len(events) == 0 {
		t.Fatal("no events from usage frame")
	}
	usageEv := events[0]
	if usageEv.Type != EventUsageUpdate {
		t.Fatalf("expected EventUsageUpdate, got %s", usageEv.Type)
	}

	var out bytes.Buffer
	if err := adapter.Emitter.EmitSanitized(context.Background(), &out, usageEv, "[SHOULD_NOT_APPEAR]"); err != nil {
		t.Fatalf("EmitSanitized on usage frame: %v", err)
	}
	// Must be byte-identical to input (identity for non-delta_text).
	if !bytes.Equal(out.Bytes(), usageFrame) {
		t.Errorf("usage frame was mutated:\nwant %q\n got %q", usageFrame, out.Bytes())
	}
	if strings.Contains(out.String(), "SHOULD_NOT_APPEAR") {
		t.Error("sanitized text leaked into non-delta_text frame — safety violation")
	}
	t.Logf("EmitSanitized/usage-identity: ok")
}

// TestEmitSanitized_OpenAI_StopFrame_Identity — [DONE] sentinel must be identity.
func TestEmitSanitized_OpenAI_StopFrame_Identity(t *testing.T) {
	doneFrame := []byte("data: [DONE]\n\n")
	adapter := mustAdapter(t, "openai")
	var events []Event
	adapter.Decoder.Decode(context.Background(), bytes.NewReader(doneFrame), func(ev Event) error { //nolint:errcheck
		events = append(events, ev)
		return nil
	})
	stopEv := events[0]

	var out bytes.Buffer
	adapter.Emitter.EmitSanitized(context.Background(), &out, stopEv, "REPLACED") //nolint:errcheck
	if !bytes.Equal(out.Bytes(), doneFrame) {
		t.Errorf("stop frame was mutated: %q", out.Bytes())
	}
}

func TestEmitSanitized_Anthropic_DeltaText_ReplacesContent(t *testing.T) {
	original := []byte(
		"event: content_block_delta\n" +
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"email user@example.com"}}` + "\n\n")
	sanitized := "[redacted:email]"
	events := decodeEvents(t, "anthropic", original)
	if len(events) != 1 || events[0].Type != EventDeltaText {
		t.Fatalf("expected one delta event, got %+v", events)
	}

	var out bytes.Buffer
	if err := mustAdapter(t, "anthropic").Emitter.EmitSanitized(context.Background(), &out, events[0], sanitized); err != nil {
		t.Fatalf("EmitSanitized: %v", err)
	}
	output := out.String()
	if !strings.HasPrefix(output, "event: content_block_delta\n") || !strings.HasSuffix(output, "\n\n") {
		t.Fatalf("invalid Anthropic SSE output: %q", output)
	}
	if !strings.Contains(output, sanitized) || strings.Contains(output, "user@example.com") {
		t.Fatalf("Anthropic sanitize failed: %s", output)
	}
	if !strings.Contains(output, `"type":"content_block_delta"`) || !strings.Contains(output, `"type":"text_delta"`) {
		t.Fatalf("Anthropic sanitize lost structural fields: %s", output)
	}
}

func TestEmitSanitized_Gemini_DeltaText_ReplacesContent(t *testing.T) {
	original := []byte(`data: {"candidates":[{"content":{"parts":[{"text":"email user@example.com"},{"text":" more"}],"role":"model"}}],"modelVersion":"gemini-1.5-pro"}` + "\n\n")
	sanitized := "[redacted:email]"
	events := decodeEvents(t, "gemini", original)
	if len(events) != 1 || events[0].Type != EventDeltaText {
		t.Fatalf("expected one delta event, got %+v", events)
	}

	var out bytes.Buffer
	if err := mustAdapter(t, "gemini").Emitter.EmitSanitized(context.Background(), &out, events[0], sanitized); err != nil {
		t.Fatalf("EmitSanitized: %v", err)
	}
	output := out.String()
	if !strings.HasPrefix(output, "data: ") || !strings.HasSuffix(output, "\n\n") {
		t.Fatalf("invalid Gemini SSE output: %q", output)
	}
	if !strings.Contains(output, sanitized) || strings.Contains(output, "user@example.com") || strings.Contains(output, " more") {
		t.Fatalf("Gemini sanitize failed: %s", output)
	}
	if !strings.Contains(output, `"modelVersion":"gemini-1.5-pro"`) || !strings.Contains(output, `"role":"model"`) {
		t.Fatalf("Gemini sanitize lost structural fields: %s", output)
	}
}

func TestEmitSanitized_Gemini_TextWithUsage_PreservesUsage(t *testing.T) {
	original := []byte(`data: {"candidates":[{"content":{"parts":[{"text":"email user@example.com"}],"role":"model"}}],"modelVersion":"gemini-1.5-pro","usageMetadata":{"promptTokenCount":4,"candidatesTokenCount":1,"totalTokenCount":5}}` + "\n\n")
	sanitized := "[redacted:email]"
	events := decodeEvents(t, "gemini", original)
	if len(events) != 1 || events[0].Type != EventDeltaText {
		t.Fatalf("expected one delta event, got %+v", events)
	}

	var out bytes.Buffer
	if err := mustAdapter(t, "gemini").Emitter.EmitSanitized(context.Background(), &out, events[0], sanitized); err != nil {
		t.Fatalf("EmitSanitized: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, sanitized) || strings.Contains(output, "user@example.com") {
		t.Fatalf("Gemini text+usage sanitize failed: %s", output)
	}
	if !strings.Contains(output, `"usageMetadata"`) || !strings.Contains(output, `"totalTokenCount":5`) {
		t.Fatalf("Gemini text+usage sanitize lost usage metadata: %s", output)
	}
}

func TestEmitSanitized_OllamaChat_DeltaText_ReplacesContent(t *testing.T) {
	original := []byte(`{"model":"llama3","message":{"role":"assistant","content":"email user@example.com"},"done":false}` + "\n")
	sanitized := "[redacted:email]"
	events := decodeEvents(t, "ollama", original)
	if len(events) != 1 || events[0].Type != EventDeltaText {
		t.Fatalf("expected one delta event, got %+v", events)
	}

	var out bytes.Buffer
	if err := mustAdapter(t, "ollama").Emitter.EmitSanitized(context.Background(), &out, events[0], sanitized); err != nil {
		t.Fatalf("EmitSanitized: %v", err)
	}
	output := out.String()
	if !strings.HasSuffix(output, "\n") {
		t.Fatalf("Ollama output must remain NDJSON line: %q", output)
	}
	if !strings.Contains(output, sanitized) || strings.Contains(output, "user@example.com") {
		t.Fatalf("Ollama chat sanitize failed: %s", output)
	}
	if !strings.Contains(output, `"role":"assistant"`) || !strings.Contains(output, `"model":"llama3"`) {
		t.Fatalf("Ollama chat sanitize lost structural fields: %s", output)
	}
}

func TestEmitSanitized_OllamaGenerate_DeltaText_ReplacesResponse(t *testing.T) {
	original := []byte(`{"model":"llama3","response":"email user@example.com","done":false}` + "\n")
	sanitized := "[redacted:email]"
	events := decodeEvents(t, "ollama", original)
	if len(events) != 1 || events[0].Type != EventDeltaText {
		t.Fatalf("expected one delta event, got %+v", events)
	}

	var out bytes.Buffer
	if err := mustAdapter(t, "ollama").Emitter.EmitSanitized(context.Background(), &out, events[0], sanitized); err != nil {
		t.Fatalf("EmitSanitized: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, sanitized) || strings.Contains(output, "user@example.com") {
		t.Fatalf("Ollama generate sanitize failed: %s", output)
	}
	if strings.Contains(output, `"message"`) {
		t.Fatalf("Ollama generate sanitize must not synthesize chat message: %s", output)
	}
}

func TestEmitSanitized_Anthropic_EmptyDelta_Identity(t *testing.T) {
	original := []byte(
		"event: content_block_start\n" +
			`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n")
	events := decodeEvents(t, "anthropic", original)
	if len(events) != 1 || events[0].Type != EventDeltaText || events[0].Text != "" {
		t.Fatalf("expected empty delta event, got %+v", events)
	}

	var out bytes.Buffer
	if err := mustAdapter(t, "anthropic").Emitter.EmitSanitized(context.Background(), &out, events[0], "MUTATED"); err != nil {
		t.Fatalf("EmitSanitized: %v", err)
	}
	if !bytes.Equal(out.Bytes(), original) {
		t.Fatalf("empty Anthropic delta must remain identity:\nwant %q\n got %q", original, out.Bytes())
	}
}

func TestEmitSanitized_NonOpenAI_MalformedDelta_ReturnsError(t *testing.T) {
	cases := []string{"anthropic", "gemini", "ollama"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			ev := Event{
				Type:     EventDeltaText,
				Text:     "email user@example.com",
				RawBytes: []byte("data: {not-json}\n\n"),
			}
			var out bytes.Buffer
			err := mustAdapter(t, name).Emitter.EmitSanitized(context.Background(), &out, ev, "[redacted:email]")
			if err == nil {
				t.Fatal("EmitSanitized must fail on malformed delta JSON")
			}
			if out.Len() != 0 {
				t.Fatalf("malformed sanitize must not emit partial bytes: %q", out.String())
			}
		})
	}
}

// TestEmitSanitized_AllAdapters_NonDeltaText_Identity — regression guard:
// all adapters must emit identity for non-delta_text events in EmitSanitized.
func TestEmitSanitized_AllAdapters_NonDeltaText_Identity(t *testing.T) {
	// A generic "unknown chunk" event with known RawBytes.
	rawBytes := []byte(": keepalive\n\n")
	ev := Event{Type: EventUnknownChunk, RawBytes: rawBytes}

	for _, name := range SupportedProviders() {
		t.Run(name, func(t *testing.T) {
			adapter := mustAdapter(t, name)
			var out bytes.Buffer
			if err := adapter.Emitter.EmitSanitized(context.Background(), &out, ev, "MUTATED"); err != nil {
				t.Fatalf("EmitSanitized error: %v", err)
			}
			if bytes.Contains(out.Bytes(), []byte("MUTATED")) {
				t.Errorf("%s: sanitized text leaked into non-delta_text frame", name)
			}
		})
	}
}

// roundTrip — helper: decode → собрать events → emit всё в buffer.
// Возвращает итоговые bytes, events, error.
func roundTrip(a Adapter, input []byte) ([]byte, []Event, error) {
	ctx := context.Background()
	var events []Event
	err := a.Decoder.Decode(ctx, bytes.NewReader(input), func(ev Event) error {
		events = append(events, ev)
		return nil
	})
	if err != nil {
		return nil, events, err
	}
	var out bytes.Buffer
	for _, ev := range events {
		if err := a.Emitter.Emit(ctx, &out, ev); err != nil {
			return nil, events, err
		}
	}
	return out.Bytes(), events, nil
}

func mustAdapter(t *testing.T, name string) Adapter {
	t.Helper()
	a, ok := AdapterForProvider(name)
	if !ok {
		t.Fatalf("no adapter for provider %q", name)
	}
	return a
}

func decodeEvents(t *testing.T, provider string, input []byte) []Event {
	t.Helper()
	adapter := mustAdapter(t, provider)
	var events []Event
	if err := adapter.Decoder.Decode(context.Background(), bytes.NewReader(input), func(ev Event) error {
		events = append(events, ev)
		return nil
	}); err != nil {
		t.Fatalf("%s decode: %v", provider, err)
	}
	return events
}

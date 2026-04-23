package streaming

import (
	"bytes"
	"context"
	"testing"
)

// TestRoundTrip_BytesIdentity — ядро F7.1 (RFC §8.6 acceptance
// criteria §20 / decisions §21). Для каждого canonical fixture:
//   decode(X) → emit каждого Event в порядке → получаем X (byte-identical).
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

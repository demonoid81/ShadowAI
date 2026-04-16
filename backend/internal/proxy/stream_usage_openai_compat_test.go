package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

// --- patchOpenAIStreamOptions ---

func TestPatchOpenAIStreamOptions_AddsToStreamingRequest(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","stream":true,"messages":[]}`)
	out, err := patchOpenAIStreamOptions(body, true)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	opts, ok := raw["stream_options"].(map[string]any)
	if !ok {
		t.Fatalf("stream_options отсутствует в результате: %s", out)
	}
	if v, _ := opts["include_usage"].(bool); !v {
		t.Errorf("include_usage != true: %v", opts["include_usage"])
	}
}

func TestPatchOpenAIStreamOptions_SkipsNonStreaming(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","stream":false,"messages":[]}`)
	out, err := patchOpenAIStreamOptions(body, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(body) {
		t.Errorf("non-streaming запрос не должен модифицироваться:\n  in:  %s\n  out: %s", body, out)
	}
}

func TestPatchOpenAIStreamOptions_SkipsWhenStreamMissing(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[]}`)
	out, err := patchOpenAIStreamOptions(body, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(body) {
		t.Errorf("отсутствие stream: не должно триггерить модификацию:\n  in:  %s\n  out: %s", body, out)
	}
}

func TestPatchOpenAIStreamOptions_PreservesExistingOptions(t *testing.T) {
	// Client передал stream_options с другим ключом — его надо сохранить.
	body := []byte(`{"stream":true,"stream_options":{"something_else":true}}`)
	out, err := patchOpenAIStreamOptions(body, true)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	_ = json.Unmarshal(out, &raw)
	opts := raw["stream_options"].(map[string]any)
	if v, _ := opts["something_else"].(bool); !v {
		t.Errorf("существующий stream_options.something_else потерян: %v", opts)
	}
	if v, _ := opts["include_usage"].(bool); !v {
		t.Errorf("include_usage не установлен: %v", opts)
	}
}

func TestPatchOpenAIStreamOptions_NoopIfAlreadyTrue(t *testing.T) {
	body := []byte(`{"stream":true,"stream_options":{"include_usage":true}}`)
	out, err := patchOpenAIStreamOptions(body, true)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	_ = json.Unmarshal(out, &raw)
	opts := raw["stream_options"].(map[string]any)
	if v, _ := opts["include_usage"].(bool); !v {
		t.Errorf("include_usage должен остаться true: %v", opts)
	}
}

func TestPatchOpenAIStreamOptions_OverridesClientFalse(t *testing.T) {
	// Клиент явно попросил include_usage=false — accounting важнее,
	// overwrite на true.
	body := []byte(`{"stream":true,"stream_options":{"include_usage":false}}`)
	out, err := patchOpenAIStreamOptions(body, true)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	_ = json.Unmarshal(out, &raw)
	opts := raw["stream_options"].(map[string]any)
	if v, _ := opts["include_usage"].(bool); !v {
		t.Errorf("client-supplied include_usage=false должен быть переопределён в true, got %v", opts["include_usage"])
	}
}

func TestPatchOpenAIStreamOptions_MalformedJSONReturnsOriginal(t *testing.T) {
	body := []byte(`not json`)
	out, err := patchOpenAIStreamOptions(body, true)
	if err != nil {
		t.Errorf("malformed JSON должен вернуть nil error (fail-safe), got: %v", err)
	}
	if string(out) != string(body) {
		t.Errorf("malformed body должен быть возвращён без изменений")
	}
}

func TestPatchOpenAIStreamOptions_EmptyBody(t *testing.T) {
	out, err := patchOpenAIStreamOptions(nil, true)
	if err != nil || out != nil {
		t.Errorf("nil body: out=%v err=%v, want nil/nil", out, err)
	}
}

// --- parseOpenAICompatStreamUsage ---

func TestParseOpenAICompatStreamUsage_FinalUsageChunk(t *testing.T) {
	// Канонический OpenAI SSE stream с include_usage=true.
	body := []byte("" +
		`data: {"model":"gpt-4o-mini","choices":[{"delta":{"content":"Hello"}}]}` + "\n\n" +
		`data: {"model":"gpt-4o-mini","choices":[{"delta":{"content":" world"}}]}` + "\n\n" +
		`data: {"model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}` + "\n\n" +
		`data: [DONE]` + "\n\n")

	u, err := parseOpenAICompatStreamUsage(body, "gpt-4o-mini", openAIPricing, openAIFallbackPricing)
	if err != nil {
		t.Fatal(err)
	}
	if !u.Found {
		t.Error("Found=false, want true")
	}
	if u.PromptTokens != 10 || u.CompletionTokens != 2 || u.TotalTokens != 12 {
		t.Errorf("tokens %d/%d/%d, want 10/2/12", u.PromptTokens, u.CompletionTokens, u.TotalTokens)
	}
	if u.Model != "gpt-4o-mini" {
		t.Errorf("model = %q, want gpt-4o-mini", u.Model)
	}
	// gpt-4o-mini: 0.15e-6 * 10 + 0.60e-6 * 2 = 2.7e-6
	const want = 2.7e-6
	if u.CostUSD < want*0.99 || u.CostUSD > want*1.01 {
		t.Errorf("cost = %g, want ~%g", u.CostUSD, want)
	}
}

func TestParseOpenAICompatStreamUsage_NoUsageFoundFalse(t *testing.T) {
	// Поток без финального usage chunk'а (client не просил include_usage).
	body := []byte("" +
		`data: {"model":"gpt-4o","choices":[{"delta":{"content":"hi"}}]}` + "\n\n" +
		`data: [DONE]` + "\n\n")

	u, err := parseOpenAICompatStreamUsage(body, "gpt-4o", openAIPricing, openAIFallbackPricing)
	if err != nil {
		t.Fatal(err)
	}
	if u.Found {
		t.Errorf("Found=true без usage chunk'а; хотелось Found=false")
	}
	if u.CostUSD != 0 {
		t.Errorf("cost = %g при Found=false; по контракту cost должен быть 0", u.CostUSD)
	}
}

func TestParseOpenAICompatStreamUsage_OpenRouterCommentSkipped(t *testing.T) {
	// OpenRouter шлёт ": OPENROUTER PROCESSING" как keepalive.
	body := []byte("" +
		": OPENROUTER PROCESSING\n\n" +
		`data: {"choices":[{"delta":{"content":"x"}}]}` + "\n\n" +
		": OPENROUTER PROCESSING\n\n" +
		`data: {"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}` + "\n\n" +
		`data: [DONE]` + "\n\n")

	u, err := parseOpenAICompatStreamUsage(body, "openai/gpt-4o", openRouterPricing, openRouterFallbackPricing)
	if err != nil {
		t.Fatal(err)
	}
	if !u.Found || u.PromptTokens != 5 || u.CompletionTokens != 3 {
		t.Errorf("usage = %+v, want 5/3 с Found=true (comments не должны ломать парсинг)", u)
	}
}

func TestParseOpenAICompatStreamUsage_OpenRouterCostAsSourceOfTruth(t *testing.T) {
	// OpenRouter возвращает usage.cost как authoritative billing.
	// Этот cost должен переиспользоваться вместо локального pricing lookup.
	body := []byte("" +
		`data: {"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150,"cost":0.0042}}` + "\n\n" +
		`data: [DONE]` + "\n\n")

	u, err := parseOpenAICompatStreamUsage(body, "openai/gpt-4o", openRouterPricing, openRouterFallbackPricing)
	if err != nil {
		t.Fatal(err)
	}
	if !u.Found {
		t.Fatal("Found=false")
	}
	// cost из usage, а не пересчёт через pricing table.
	if u.CostUSD != 0.0042 {
		t.Errorf("cost = %g, want 0.0042 (usage.cost — source of truth для OpenRouter)", u.CostUSD)
	}
}

func TestParseOpenAICompatStreamUsage_MidStreamErrorIgnored(t *testing.T) {
	// Mid-stream error frame от OpenRouter: non-standard schema,
	// не должен ломать парсер — continue до следующего data.
	body := []byte("" +
		`data: {"error":{"code":"RATE_LIMIT","message":"slow down"},"finish_reason":"error"}` + "\n\n" +
		`data: [DONE]` + "\n\n")

	u, err := parseOpenAICompatStreamUsage(body, "model", openAIPricing, openAIFallbackPricing)
	if err != nil {
		t.Errorf("mid-stream error не должен вызывать parser error, got: %v", err)
	}
	if u.Found {
		t.Errorf("Found=true при error-only frame; want false")
	}
}

func TestParseOpenAICompatStreamUsage_LastUsageWins(t *testing.T) {
	// Если несколько chunks содержат usage, берём последний.
	body := []byte("" +
		`data: {"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}` + "\n\n" +
		`data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}` + "\n\n" +
		`data: [DONE]` + "\n\n")

	u, err := parseOpenAICompatStreamUsage(body, "gpt-4o-mini", openAIPricing, openAIFallbackPricing)
	if err != nil {
		t.Fatal(err)
	}
	if u.PromptTokens != 10 || u.CompletionTokens != 20 {
		t.Errorf("tokens = %d/%d, want 10/20 (last usage wins)", u.PromptTokens, u.CompletionTokens)
	}
}

func TestParseOpenAICompatStreamUsage_ModelFallbackToRequest(t *testing.T) {
	// Некоторые провайдеры не возвращают model в chunks. Fallback на requestModel.
	body := []byte("" +
		`data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}` + "\n\n")

	u, err := parseOpenAICompatStreamUsage(body, "gpt-4o-mini", openAIPricing, openAIFallbackPricing)
	if err != nil {
		t.Fatal(err)
	}
	if !u.Found {
		t.Fatal("Found=false")
	}
	// cost должен считаться по gpt-4o-mini pricing (прошёл requestModel, т.к. chunk без model)
	const want = 0.15e-6*10 + 0.60e-6*5
	if u.CostUSD < want*0.99 || u.CostUSD > want*1.01 {
		t.Errorf("cost = %g, want ~%g (pricing по requestModel fallback)", u.CostUSD, want)
	}
}

func TestParseOpenAICompatStreamUsage_EmptyBody(t *testing.T) {
	u, err := parseOpenAICompatStreamUsage(nil, "m", openAIPricing, openAIFallbackPricing)
	if err != nil {
		t.Errorf("err = %v, want nil для пустого body", err)
	}
	if u.Found {
		t.Error("Found=true для пустого body")
	}
}

// --- Provider integration через ParseStreamUsage ---

func TestOpenAIProvider_StreamUsageDelegation(t *testing.T) {
	p := NewOpenAIProvider("test-key")
	body := []byte(`data: {"model":"gpt-4o","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}` + "\n\n")

	u, err := p.ParseStreamUsage(body, "gpt-4o")
	if err != nil {
		t.Fatal(err)
	}
	if !u.Found {
		t.Error("OpenAIProvider.ParseStreamUsage должен вернуть Found=true на валидном stream'е")
	}
	if u.Model != "gpt-4o" {
		t.Errorf("model = %q, want gpt-4o", u.Model)
	}
}

func TestOpenRouterProvider_StreamUsageWithCost(t *testing.T) {
	p := NewOpenRouterProvider("test-key")
	body := []byte(`data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15,"cost":0.001}}` + "\n\n")

	u, err := p.ParseStreamUsage(body, "openai/gpt-4o")
	if err != nil {
		t.Fatal(err)
	}
	if u.CostUSD != 0.001 {
		t.Errorf("OpenRouter usage.cost должен быть source of truth, got %g", u.CostUSD)
	}
}

func TestMistralProvider_StreamUsageBestEffort(t *testing.T) {
	// Mistral docs показывают "usage":{} в streaming. Парсер обязан
	// вернуть Found=false без ошибки.
	p := NewMistralProvider("test-key")
	body := []byte(`data: {"choices":[{"delta":{"content":"hi"}}],"usage":{}}` + "\n\n" +
		`data: [DONE]` + "\n\n")

	u, err := p.ParseStreamUsage(body, "mistral-large-latest")
	if err != nil {
		t.Fatal(err)
	}
	if u.Found {
		t.Errorf("Mistral empty usage должен дать Found=false, got %+v", u)
	}
}

func TestGroqProvider_StreamUsageBestEffort(t *testing.T) {
	p := NewGroqProvider("test-key")
	// Groq docs не фиксируют include_usage; симулируем типичный поток без usage.
	body := []byte(`data: {"choices":[{"delta":{"content":"hi"}}]}` + "\n\n" +
		`data: [DONE]` + "\n\n")

	u, err := p.ParseStreamUsage(body, "llama-3.1-8b-instant")
	if err != nil {
		t.Fatal(err)
	}
	if u.Found {
		t.Errorf("Groq без usage должен дать Found=false, got %+v", u)
	}
}

// --- BuildRequest integration с InjectIncludeUsage ---

func TestOpenAIProvider_BuildRequestInjectsIncludeUsage(t *testing.T) {
	p := NewOpenAIProvider("key")
	body := []byte(`{"model":"gpt-4o","stream":true,"messages":[]}`)

	req, err := p.BuildRequest(t.Context(), body, "gpt-4o")
	if err != nil {
		t.Fatal(err)
	}
	// Вычитаем body обратно из request.
	buf := make([]byte, 4096)
	n, _ := req.Body.Read(buf)
	got := string(buf[:n])

	if !strings.Contains(got, `"include_usage":true`) {
		t.Errorf("OpenAI streaming request должен содержать include_usage=true, got: %s", got)
	}
}

func TestMistralProvider_BuildRequestDoesNotInject(t *testing.T) {
	// Mistral best-effort, НЕ inject'им (docs не подтверждают поддержку).
	p := NewMistralProvider("key")
	body := []byte(`{"model":"mistral-large-latest","stream":true,"messages":[]}`)

	req, err := p.BuildRequest(t.Context(), body, "mistral-large-latest")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _ := req.Body.Read(buf)
	got := string(buf[:n])

	if strings.Contains(got, "include_usage") {
		t.Errorf("Mistral НЕ должен inject'ить include_usage, got: %s", got)
	}
}

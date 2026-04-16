package proxy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRegistryRegisterAndGet(t *testing.T) {
	reg := NewRegistry()
	p := NewOpenAIProvider("test-key")
	reg.Register(p)

	got, ok := reg.Get("openai")
	if !ok {
		t.Fatal("expected provider to be found")
	}
	if got.Name() != "openai" {
		t.Errorf("expected name 'openai', got %q", got.Name())
	}
}

func TestRegistryGetUnknown(t *testing.T) {
	reg := NewRegistry()
	_, ok := reg.Get("nonexistent")
	if ok {
		t.Fatal("expected provider not to be found")
	}
}

func TestRegistryList(t *testing.T) {
	reg := NewRegistry()
	reg.Register(NewOpenAIProvider("k"))
	reg.Register(NewAnthropicProvider("k"))

	names := reg.List()
	if len(names) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(names))
	}
}

// --- OpenAI ---

func TestOpenAIBuildRequest(t *testing.T) {
	p := NewOpenAIProvider("sk-test-key")
	body := []byte(`{"model":"gpt-4o","messages":[]}`)

	req, err := p.BuildRequest(context.Background(), body, "gpt-4o")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.URL.String() != "https://api.openai.com/v1/chat/completions" {
		t.Errorf("unexpected URL: %s", req.URL.String())
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sk-test-key" {
		t.Errorf("unexpected Authorization header: %s", got)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("unexpected Content-Type: %s", got)
	}
}

func TestOpenAIParseResponse(t *testing.T) {
	p := NewOpenAIProvider("key")
	resp := `{"model":"gpt-4o-mini","usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`

	pt, ct, tt, cost, err := p.ParseResponse([]byte(resp))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pt != 100 || ct != 50 || tt != 150 {
		t.Errorf("unexpected tokens: pt=%d ct=%d tt=%d", pt, ct, tt)
	}
	if cost <= 0 {
		t.Errorf("expected positive cost, got %f", cost)
	}
}

func TestOpenAIDefaultModel(t *testing.T) {
	p := NewOpenAIProvider("key")
	if p.DefaultModel() != "gpt-4o-mini" {
		t.Errorf("unexpected default model: %s", p.DefaultModel())
	}
}

func TestOpenAIStreamFormat(t *testing.T) {
	p := NewOpenAIProvider("key")
	if p.StreamFormat() != StreamSSE {
		t.Error("expected StreamSSE")
	}
}

// --- Anthropic ---

func TestAnthropicBuildRequest(t *testing.T) {
	p := NewAnthropicProvider("sk-ant-test")
	body := []byte(`{"model":"claude-3-5-sonnet-20241022","messages":[]}`)

	req, err := p.BuildRequest(context.Background(), body, "claude-3-5-sonnet-20241022")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.URL.String() != "https://api.anthropic.com/v1/messages" {
		t.Errorf("unexpected URL: %s", req.URL.String())
	}
	if got := req.Header.Get("x-api-key"); got != "sk-ant-test" {
		t.Errorf("unexpected x-api-key header: %s", got)
	}
	if got := req.Header.Get("anthropic-version"); got != "2023-06-01" {
		t.Errorf("unexpected anthropic-version header: %s", got)
	}
}

func TestAnthropicParseResponse(t *testing.T) {
	p := NewAnthropicProvider("key")
	resp := `{"usage":{"input_tokens":200,"output_tokens":80}}`

	pt, ct, tt, cost, err := p.ParseResponse([]byte(resp))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pt != 200 || ct != 80 || tt != 280 {
		t.Errorf("unexpected tokens: pt=%d ct=%d tt=%d", pt, ct, tt)
	}
	if cost <= 0 {
		t.Errorf("expected positive cost, got %f", cost)
	}
}

// --- Gemini ---

func TestGeminiBuildRequest(t *testing.T) {
	p := NewGeminiProvider("gem-key-123")
	body := []byte(`{"contents":[]}`)

	req, err := p.BuildRequest(context.Background(), body, "gemini-1.5-pro")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	url := req.URL.String()
	if !strings.Contains(url, "gemini-1.5-pro:generateContent") {
		t.Errorf("URL missing model: %s", url)
	}
	if !strings.Contains(url, "key=gem-key-123") {
		t.Errorf("URL missing API key: %s", url)
	}
}

func TestGeminiBuildRequestDefaultModel(t *testing.T) {
	p := NewGeminiProvider("key")
	req, err := p.BuildRequest(context.Background(), []byte(`{}`), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(req.URL.String(), "gemini-1.5-flash") {
		t.Errorf("expected default model in URL: %s", req.URL.String())
	}
}

func TestGeminiParseResponse(t *testing.T) {
	p := NewGeminiProvider("key")
	resp := `{"usageMetadata":{"promptTokenCount":50,"candidatesTokenCount":30,"totalTokenCount":80}}`

	pt, ct, tt, cost, err := p.ParseResponse([]byte(resp))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pt != 50 || ct != 30 || tt != 80 {
		t.Errorf("unexpected tokens: pt=%d ct=%d tt=%d", pt, ct, tt)
	}
	if cost <= 0 {
		t.Errorf("expected positive cost, got %f", cost)
	}
}

// --- Mistral ---

func TestMistralBuildRequest(t *testing.T) {
	p := NewMistralProvider("mist-key")
	req, err := p.BuildRequest(context.Background(), []byte(`{}`), "mistral-small-latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.String() != "https://api.mistral.ai/v1/chat/completions" {
		t.Errorf("unexpected URL: %s", req.URL.String())
	}
	if got := req.Header.Get("Authorization"); got != "Bearer mist-key" {
		t.Errorf("unexpected Authorization: %s", got)
	}
}

func TestMistralName(t *testing.T) {
	p := NewMistralProvider("key")
	if p.Name() != "mistral" {
		t.Errorf("unexpected name: %s", p.Name())
	}
}

// TestMistralParseResponse_ModelSpecificPricing — regression: до фикса
// cost считался по fallback pricing независимо от resp.model, потому что
// OpenAICompat.ParseResponse передавал "" в calculateProviderCost.
// Теперь model-specific pricing работает для всех OpenAI-compatible
// провайдеров (Mistral, Groq, OpenRouter).
func TestMistralParseResponse_ModelSpecificPricing(t *testing.T) {
	p := NewMistralProvider("key")
	// mistral-large: {3.0/1M, 9.0/1M}; fallback mistral-small: {1.0/1M, 3.0/1M}
	// 100 prompt + 50 completion:
	//   large pricing    → 100*3e-6 + 50*9e-6 = 7.5e-4
	//   fallback pricing → 100*1e-6 + 50*3e-6 = 2.5e-4
	resp := `{"model":"mistral-large-latest","usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`
	_, _, _, cost, err := p.ParseResponse([]byte(resp))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const wantLarge = 7.5e-4
	if cost < wantLarge*0.99 || cost > wantLarge*1.01 {
		t.Errorf("cost = %g, expected ~%g (model-specific pricing). Если похоже на 2.5e-4 — баг вернулся: cost считается по fallback", cost, wantLarge)
	}
}

// TestOpenAICompat_ParseResponse_DefaultsToProviderDefault — если resp
// не содержит model (некоторые реализации опускают поле), fallback идёт
// на p.Default модель, а не на "" → всё ещё используется model-specific
// pricing провайдера по умолчанию.
func TestOpenAICompat_ParseResponse_DefaultsToProviderDefault(t *testing.T) {
	p := NewMistralProvider("key")
	// Default для Mistral — mistral-small-latest: {1.0/1M, 3.0/1M}
	resp := `{"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`
	_, _, _, cost, err := p.ParseResponse([]byte(resp))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const wantSmall = 2.5e-4 // mistral-small-latest pricing
	if cost < wantSmall*0.99 || cost > wantSmall*1.01 {
		t.Errorf("cost = %g, expected ~%g (default model pricing)", cost, wantSmall)
	}
}

// --- Groq ---

func TestGroqBuildRequest(t *testing.T) {
	p := NewGroqProvider("groq-key")
	req, err := p.BuildRequest(context.Background(), []byte(`{}`), "llama-3.1-8b-instant")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.String() != "https://api.groq.com/openai/v1/chat/completions" {
		t.Errorf("unexpected URL: %s", req.URL.String())
	}
}

func TestGroqName(t *testing.T) {
	p := NewGroqProvider("key")
	if p.Name() != "groq" {
		t.Errorf("unexpected name: %s", p.Name())
	}
}

// --- OpenRouter ---

func TestOpenRouterBuildRequest(t *testing.T) {
	p := NewOpenRouterProvider("or-key")
	req, err := p.BuildRequest(context.Background(), []byte(`{}`), "openai/gpt-4o")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.String() != "https://openrouter.ai/api/v1/chat/completions" {
		t.Errorf("unexpected URL: %s", req.URL.String())
	}
}

func TestOpenRouterName(t *testing.T) {
	p := NewOpenRouterProvider("key")
	if p.Name() != "openrouter" {
		t.Errorf("unexpected name: %s", p.Name())
	}
}

// --- Ollama ---

func TestOllamaBuildRequest(t *testing.T) {
	p := NewOllamaProvider("")
	req, err := p.BuildRequest(context.Background(), []byte(`{}`), "llama3.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.String() != "http://localhost:11434/api/chat" {
		t.Errorf("unexpected URL: %s", req.URL.String())
	}
	// Ollama should not have Authorization header
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("unexpected Authorization header: %s", got)
	}
}

func TestOllamaCustomURL(t *testing.T) {
	p := NewOllamaProvider("http://myhost:11434")
	req, err := p.BuildRequest(context.Background(), []byte(`{}`), "llama3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.String() != "http://myhost:11434/api/chat" {
		t.Errorf("unexpected URL: %s", req.URL.String())
	}
}

func TestOllamaParseResponse(t *testing.T) {
	p := NewOllamaProvider("")
	resp := `{"message":{"content":"Hello"},"prompt_eval_count":10,"eval_count":5}`

	pt, ct, tt, cost, err := p.ParseResponse([]byte(resp))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pt != 10 || ct != 5 || tt != 15 {
		t.Errorf("unexpected tokens: pt=%d ct=%d tt=%d", pt, ct, tt)
	}
	if cost != 0 {
		t.Errorf("expected zero cost for Ollama, got %f", cost)
	}
}

func TestOllamaStreamFormat(t *testing.T) {
	p := NewOllamaProvider("")
	if p.StreamFormat() != StreamNDJSON {
		t.Error("expected StreamNDJSON")
	}
}

// --- Cross-cutting ---

func TestAllProvidersSatisfyInterface(t *testing.T) {
	providers := []Provider{
		NewOpenAIProvider("k"),
		NewAnthropicProvider("k"),
		NewGeminiProvider("k"),
		NewMistralProvider("k"),
		NewGroqProvider("k"),
		NewOpenRouterProvider("k"),
		NewOllamaProvider(""),
	}

	for _, p := range providers {
		if p.Name() == "" {
			t.Error("provider name must not be empty")
		}
		if p.DefaultModel() == "" {
			t.Errorf("provider %s: default model must not be empty", p.Name())
		}
		if len(p.SupportedModels()) == 0 {
			t.Errorf("provider %s: must have at least one supported model", p.Name())
		}
	}
}

func TestParseResponseInvalidJSON(t *testing.T) {
	providers := []Provider{
		NewOpenAIProvider("k"),
		NewAnthropicProvider("k"),
		NewGeminiProvider("k"),
		NewMistralProvider("k"),
		NewGroqProvider("k"),
		NewOpenRouterProvider("k"),
		NewOllamaProvider(""),
	}

	for _, p := range providers {
		_, _, _, _, err := p.ParseResponse([]byte(`{invalid`))
		if err == nil {
			t.Errorf("provider %s: expected error for invalid JSON", p.Name())
		}
	}
}

func TestCalculateProviderCost(t *testing.T) {
	pricing := map[string][2]float64{
		"model-a": {1.0 / 1_000_000, 2.0 / 1_000_000},
	}
	fallback := [2]float64{0.5 / 1_000_000, 1.0 / 1_000_000}

	// Known model
	cost := calculateProviderCost(pricing, fallback, "model-a", 1000, 500)
	expected := 1000*(1.0/1_000_000) + 500*(2.0/1_000_000)
	if cost != expected {
		t.Errorf("expected %f, got %f", expected, cost)
	}

	// Fallback model
	cost = calculateProviderCost(pricing, fallback, "unknown", 1000, 500)
	expected = 1000*(0.5/1_000_000) + 500*(1.0/1_000_000)
	if cost != expected {
		t.Errorf("expected %f, got %f", expected, cost)
	}
}

// Verify OpenAI-compat providers correctly serialize request bodies
func TestOpenAICompatParseResponse(t *testing.T) {
	resp := `{"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`

	providers := []Provider{
		NewMistralProvider("k"),
		NewGroqProvider("k"),
		NewOpenRouterProvider("k"),
	}

	for _, p := range providers {
		pt, ct, tt, _, err := p.ParseResponse([]byte(resp))
		if err != nil {
			t.Fatalf("provider %s: unexpected error: %v", p.Name(), err)
		}
		if pt != 100 || ct != 50 || tt != 150 {
			t.Errorf("provider %s: unexpected tokens: pt=%d ct=%d tt=%d", p.Name(), pt, ct, tt)
		}
	}
}

// --- Model Validation ---

func TestIsModelSupported_Known(t *testing.T) {
	p := NewOpenAIProvider("k")
	if !isModelSupported(p, p.DefaultModel()) {
		t.Errorf("default model %q should be supported", p.DefaultModel())
	}
}

func TestIsModelSupported_Unknown(t *testing.T) {
	p := NewOpenAIProvider("k")
	if isModelSupported(p, "nonexistent-model-xyz") {
		t.Error("nonexistent model should not be supported")
	}
}

func TestIsModelSupported_AllProviders(t *testing.T) {
	providers := []Provider{
		NewOpenAIProvider("k"),
		NewAnthropicProvider("k"),
		NewGeminiProvider("k"),
		NewMistralProvider("k"),
		NewGroqProvider("k"),
		NewOpenRouterProvider("k"),
		NewOllamaProvider(""),
	}
	for _, p := range providers {
		// Default model must be in SupportedModels
		if !isModelSupported(p, p.DefaultModel()) {
			t.Errorf("provider %s: default model %q not in SupportedModels", p.Name(), p.DefaultModel())
		}
		// Unknown model must not be supported
		if isModelSupported(p, "definitely-not-a-real-model") {
			t.Errorf("provider %s: unknown model should not be supported", p.Name())
		}
	}
}

// --- Registry ListProviders ---

func TestRegistryListProviders(t *testing.T) {
	reg := NewRegistry()
	reg.Register(NewOpenAIProvider("k"))
	reg.Register(NewAnthropicProvider("k"))
	reg.Register(NewOllamaProvider(""))

	providers := reg.ListProviders()
	if len(providers) != 3 {
		t.Fatalf("expected 3 providers, got %d", len(providers))
	}

	names := make(map[string]bool)
	for _, p := range providers {
		names[p.Name()] = true
	}
	for _, expected := range []string{"openai", "anthropic", "ollama"} {
		if !names[expected] {
			t.Errorf("expected provider %q in list", expected)
		}
	}
}

func TestRegistryListProvidersEmpty(t *testing.T) {
	reg := NewRegistry()
	providers := reg.ListProviders()
	if len(providers) != 0 {
		t.Fatalf("expected 0 providers, got %d", len(providers))
	}
}

// Verify JSON marshal of test payloads
func TestChatRequestJSON(t *testing.T) {
	req := chatRequest{
		Model:  "gpt-4o",
		Stream: true,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(data), `"model":"gpt-4o"`) {
		t.Errorf("unexpected JSON: %s", string(data))
	}
}

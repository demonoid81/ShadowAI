package proxy

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// nonStreamingProvider — минимальная реализация Provider без
// StreamUsageProvider. Используется для проверки migration contract:
// handler должен получить Found=false без ошибки.
type nonStreamingProvider struct{}

func (nonStreamingProvider) Name() string { return "non-streaming" }
func (nonStreamingProvider) BuildRequest(_ context.Context, _ []byte, _ string) (*http.Request, error) {
	return nil, nil
}
func (nonStreamingProvider) ParseResponse(_ []byte) (int, int, int, float64, error) {
	return 0, 0, 0, 0, nil
}
func (nonStreamingProvider) StreamFormat() StreamFormat { return StreamSSE }
func (nonStreamingProvider) DefaultModel() string       { return "dummy" }
func (nonStreamingProvider) SupportedModels() []string  { return []string{"dummy"} }

// streamingProvider — реализует StreamUsageProvider с контролируемым
// возвратом для тестов.
type streamingProvider struct {
	nonStreamingProvider
	usage StreamUsage
	err   error
	// captured — что получил parser, для assert'ов.
	capturedBody  []byte
	capturedModel string
}

func (s *streamingProvider) ParseStreamUsage(body []byte, model string) (StreamUsage, error) {
	s.capturedBody = body
	s.capturedModel = model
	return s.usage, s.err
}

func TestParseStreamingUsage_NilProvider(t *testing.T) {
	usage, err := parseStreamingUsage(nil, []byte("data"), "model")
	if err != nil {
		t.Errorf("err = %v, want nil для nil provider", err)
	}
	if usage.Found {
		t.Error("Found=true для nil provider — ожидалось false")
	}
}

func TestParseStreamingUsage_ProviderWithoutSupport(t *testing.T) {
	// Migration contract: провайдер без StreamUsageProvider — не ошибка,
	// handler получает Found=false и продолжает soft-path.
	p := nonStreamingProvider{}
	usage, err := parseStreamingUsage(p, []byte("data: {}\n\n"), "gpt-4")
	if err != nil {
		t.Errorf("err = %v, want nil для провайдера без StreamUsageProvider", err)
	}
	if usage.Found {
		t.Error("Found=true для non-supporting provider — ожидалось false")
	}
}

func TestParseStreamingUsage_Delegation(t *testing.T) {
	p := &streamingProvider{
		usage: StreamUsage{
			PromptTokens:     10,
			CompletionTokens: 5,
			TotalTokens:      15,
			CostUSD:          0.001,
			Model:            "gpt-4o",
			Found:            true,
		},
	}
	body := []byte("data: sample\n\n")
	usage, err := parseStreamingUsage(p, body, "gpt-4o-requested")
	if err != nil {
		t.Fatal(err)
	}
	if !usage.Found {
		t.Error("Found=false, want true (provider вернул Found=true)")
	}
	if usage.PromptTokens != 10 || usage.CompletionTokens != 5 {
		t.Errorf("tokens = %d/%d, want 10/5", usage.PromptTokens, usage.CompletionTokens)
	}
	if usage.CostUSD != 0.001 {
		t.Errorf("cost = %g, want 0.001", usage.CostUSD)
	}
	if usage.Model != "gpt-4o" {
		t.Errorf("model = %q, want gpt-4o", usage.Model)
	}

	// Проверим, что helper передал body и model как есть, без мутаций.
	if string(p.capturedBody) != "data: sample\n\n" {
		t.Errorf("captured body = %q, want исходный", p.capturedBody)
	}
	if p.capturedModel != "gpt-4o-requested" {
		t.Errorf("captured model = %q, want 'gpt-4o-requested'", p.capturedModel)
	}
}

func TestParseStreamingUsage_ErrorPropagation(t *testing.T) {
	// Malformed SSE и т.п. — parser должен вернуть error, helper
	// пробрасывает его наружу без swallowing.
	sentinel := errors.New("malformed SSE frame")
	p := &streamingProvider{err: sentinel}

	usage, err := parseStreamingUsage(p, []byte("garbage"), "model")
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want %v (error должен пробрасываться)", err, sentinel)
	}
	// Контракт: cost > 0 при Found=false запрещён; здесь и usage нулевой.
	if usage.Found || usage.CostUSD != 0 {
		t.Errorf("usage = %+v, want zero value при ошибке", usage)
	}
}

func TestParseStreamingUsage_FoundFalseIsNotError(t *testing.T) {
	// Provider сказал "usage не пришёл" — это штатный fallback path,
	// не ошибка. Handler зарегистрирует метрику и продолжит.
	p := &streamingProvider{usage: StreamUsage{Found: false}}
	usage, err := parseStreamingUsage(p, []byte("data: {}\n\n"), "model")
	if err != nil {
		t.Errorf("err = %v, Found=false не должно быть ошибкой", err)
	}
	if usage.Found {
		t.Errorf("Found=true, want false")
	}
	if usage.CostUSD != 0 {
		t.Errorf("cost = %g при Found=false; по контракту cost > 0 запрещён", usage.CostUSD)
	}
}

// TestStreamUsage_ZeroValue — zero value безопасен для использования
// без инициализации (handler может вернуть пустой StreamUsage при
// некоторых code path'ах).
func TestStreamUsage_ZeroValue(t *testing.T) {
	var u StreamUsage
	if u.Found {
		t.Error("zero value должен иметь Found=false")
	}
	if u.CostUSD != 0 || u.TotalTokens != 0 {
		t.Errorf("zero value имеет ненулевые поля: %+v", u)
	}
}

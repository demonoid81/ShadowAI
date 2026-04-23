package streaming

// Adapter — парный интерфейс decoder+emitter, один на provider family.
// RFC §8.6: оба направления должны поставляться вместе и проходить
// round-trip тест decode(X) → emit = X на canonical fixtures.
type Adapter struct {
	Decoder Decoder
	Emitter Emitter
}

// AdapterForProvider — factory. Диспатч по provider name (как возвращает
// Provider.Name()). Возвращает (Adapter, true) если name известен и
// поддержан, (Adapter{}, false) для unsupported providers — caller
// (handler) обязан использовать buffered_fallback path.
//
// Явный маппинг (вместо коммента в RFC): OpenAI / Groq / Mistral /
// OpenRouter все используют openai-compatible pair, потому что их
// провайдерные implementations в backend/internal/proxy/provider_*.go
// embed OpenAICompatProvider. Это зафиксировано кодом, не документом,
// per RFC §9.
func AdapterForProvider(providerName string) (Adapter, bool) {
	switch providerName {
	case "openai", "groq", "mistral", "openrouter":
		return Adapter{
			Decoder: OpenAICompatDecoder{},
			Emitter: OpenAICompatEmitter{},
		}, true
	case "anthropic":
		return Adapter{
			Decoder: AnthropicDecoder{},
			Emitter: AnthropicEmitter{},
		}, true
	case "gemini":
		return Adapter{
			Decoder: GeminiDecoder{},
			Emitter: GeminiEmitter{},
		}, true
	case "ollama":
		return Adapter{
			Decoder: OllamaDecoder{},
			Emitter: OllamaEmitter{},
		}, true
	}
	return Adapter{}, false
}

// SupportedProviders возвращает список provider name'ов, для которых
// есть adapter. Используется тестами для exhaustive coverage и
// метриками для cardinality-safe labels.
func SupportedProviders() []string {
	return []string{"openai", "groq", "mistral", "openrouter", "anthropic", "gemini", "ollama"}
}

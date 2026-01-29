package proxy

var groqPricing = map[string][2]float64{
	"llama-3.1-70b-versatile": {0.59 / 1_000_000, 0.79 / 1_000_000},
	"llama-3.1-8b-instant":   {0.05 / 1_000_000, 0.08 / 1_000_000},
	"llama3-70b-8192":        {0.59 / 1_000_000, 0.79 / 1_000_000},
	"llama3-8b-8192":         {0.05 / 1_000_000, 0.08 / 1_000_000},
	"mixtral-8x7b-32768":     {0.24 / 1_000_000, 0.24 / 1_000_000},
	"gemma2-9b-it":           {0.20 / 1_000_000, 0.20 / 1_000_000},
}

var groqFallbackPricing = [2]float64{0.05 / 1_000_000, 0.08 / 1_000_000}

// GroqProvider handles Groq API requests (OpenAI-compatible).
type GroqProvider struct {
	*OpenAICompatProvider
}

// NewGroqProvider creates a new Groq provider.
func NewGroqProvider(apiKey string) *GroqProvider {
	return &GroqProvider{
		OpenAICompatProvider: &OpenAICompatProvider{
			ProviderName: "groq",
			BaseURL:      "https://api.groq.com/openai/v1/chat/completions",
			APIKey:       apiKey,
			Models: []string{
				"llama-3.1-70b-versatile",
				"llama-3.1-8b-instant",
				"llama3-70b-8192",
				"llama3-8b-8192",
				"mixtral-8x7b-32768",
				"gemma2-9b-it",
			},
			Default:  "llama-3.1-8b-instant",
			Pricing:  groqPricing,
			Fallback: groqFallbackPricing,
		},
	}
}

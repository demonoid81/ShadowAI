package proxy

var mistralPricing = map[string][2]float64{
	"mistral-large-latest":  {3.0 / 1_000_000, 9.0 / 1_000_000},
	"mistral-medium-latest": {2.7 / 1_000_000, 8.1 / 1_000_000},
	"mistral-small-latest":  {1.0 / 1_000_000, 3.0 / 1_000_000},
	"open-mistral-nemo":     {0.3 / 1_000_000, 0.3 / 1_000_000},
	"codestral-latest":      {1.0 / 1_000_000, 3.0 / 1_000_000},
}

var mistralFallbackPricing = [2]float64{1.0 / 1_000_000, 3.0 / 1_000_000}

// MistralProvider handles Mistral AI API requests (OpenAI-compatible).
type MistralProvider struct {
	*OpenAICompatProvider
}

// NewMistralProvider creates a new Mistral provider.
func NewMistralProvider(apiKey string) *MistralProvider {
	return &MistralProvider{
		OpenAICompatProvider: &OpenAICompatProvider{
			ProviderName: "mistral",
			BaseURL:      "https://api.mistral.ai/v1/chat/completions",
			APIKey:       apiKey,
			Models: []string{
				"mistral-large-latest",
				"mistral-medium-latest",
				"mistral-small-latest",
				"open-mistral-nemo",
				"codestral-latest",
			},
			Default:  "mistral-small-latest",
			Pricing:  mistralPricing,
			Fallback: mistralFallbackPricing,
		},
	}
}

package proxy

var openRouterPricing = map[string][2]float64{
	"openai/gpt-4o":                    {5.0 / 1_000_000, 15.0 / 1_000_000},
	"openai/gpt-4o-mini":               {0.15 / 1_000_000, 0.60 / 1_000_000},
	"anthropic/claude-3.5-sonnet":      {3.0 / 1_000_000, 15.0 / 1_000_000},
	"anthropic/claude-3-haiku":         {0.25 / 1_000_000, 1.25 / 1_000_000},
	"google/gemini-pro-1.5":            {3.5 / 1_000_000, 10.5 / 1_000_000},
	"meta-llama/llama-3.1-70b-instruct": {0.59 / 1_000_000, 0.79 / 1_000_000},
}

var openRouterFallbackPricing = [2]float64{1.0 / 1_000_000, 3.0 / 1_000_000}

// OpenRouterProvider handles OpenRouter API requests (OpenAI-compatible).
type OpenRouterProvider struct {
	*OpenAICompatProvider
}

// NewOpenRouterProvider creates a new OpenRouter provider.
func NewOpenRouterProvider(apiKey string) *OpenRouterProvider {
	return &OpenRouterProvider{
		OpenAICompatProvider: &OpenAICompatProvider{
			ProviderName: "openrouter",
			BaseURL:      "https://openrouter.ai/api/v1/chat/completions",
			APIKey:       apiKey,
			Models: []string{
				"openai/gpt-4o",
				"openai/gpt-4o-mini",
				"anthropic/claude-3.5-sonnet",
				"anthropic/claude-3-haiku",
				"google/gemini-pro-1.5",
				"meta-llama/llama-3.1-70b-instruct",
			},
			Default:  "openai/gpt-4o-mini",
			Pricing:  openRouterPricing,
			Fallback: openRouterFallbackPricing,
		},
	}
}

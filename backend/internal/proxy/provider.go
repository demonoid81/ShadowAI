package proxy

import (
	"context"
	"net/http"
)

// StreamFormat defines the streaming protocol used by a provider.
type StreamFormat int

const (
	StreamSSE    StreamFormat = iota // Server-Sent Events (OpenAI, Anthropic, Gemini)
	StreamNDJSON                    // Newline-delimited JSON (Ollama)
)

// Provider defines the interface for an AI provider.
type Provider interface {
	// Name returns the provider identifier (e.g. "openai", "anthropic").
	Name() string

	// BuildRequest constructs an HTTP request for the provider's API.
	BuildRequest(ctx context.Context, body []byte, model string) (*http.Request, error)

	// ParseResponse extracts token counts and cost from the provider's response body.
	ParseResponse(body []byte) (promptTokens, completionTokens, totalTokens int, cost float64, err error)

	// StreamFormat returns the streaming protocol used by this provider.
	StreamFormat() StreamFormat

	// DefaultModel returns the default model name for this provider.
	DefaultModel() string

	// SupportedModels returns a list of known model names for this provider.
	SupportedModels() []string
}

// calculateProviderCost computes cost given a pricing map and token counts.
func calculateProviderCost(pricing map[string][2]float64, fallback [2]float64, model string, promptTokens, completionTokens int) float64 {
	prices, ok := pricing[model]
	if !ok {
		prices = fallback
	}
	return float64(promptTokens)*prices[0] + float64(completionTokens)*prices[1]
}

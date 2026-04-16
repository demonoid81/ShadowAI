package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

var anthropicPricing = map[string][2]float64{
	"claude-3-5-sonnet-20241022": {3.0 / 1_000_000, 15.0 / 1_000_000},
	"claude-3-5-haiku-20241022":  {1.0 / 1_000_000, 5.0 / 1_000_000},
	"claude-3-opus-20240229":     {15.0 / 1_000_000, 75.0 / 1_000_000},
	"claude-3-sonnet-20240229":   {3.0 / 1_000_000, 15.0 / 1_000_000},
	"claude-3-haiku-20240307":    {0.25 / 1_000_000, 1.25 / 1_000_000},
}

var anthropicFallbackPricing = [2]float64{3.0 / 1_000_000, 15.0 / 1_000_000}

type anthropicResponse struct {
	// Model возвращается Anthropic в non-stream ответе и является
	// источником истины для model-specific pricing lookup. Ранее cost
	// считался с пустым model, что всегда попадало в fallback pricing —
	// для sonnet/opus это было материально неточно.
	Model string `json:"model,omitempty"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// AnthropicProvider handles Anthropic Messages API requests.
type AnthropicProvider struct {
	apiKey string
}

// NewAnthropicProvider creates a new Anthropic provider.
func NewAnthropicProvider(apiKey string) *AnthropicProvider {
	return &AnthropicProvider{apiKey: apiKey}
}

func (p *AnthropicProvider) Name() string { return "anthropic" }

func (p *AnthropicProvider) BuildRequest(ctx context.Context, body []byte, model string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("anthropic: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	return req, nil
}

func (p *AnthropicProvider) ParseResponse(body []byte) (promptTokens, completionTokens, totalTokens int, cost float64, err error) {
	var resp anthropicResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("anthropic: parse response: %w", err)
	}
	pt := resp.Usage.InputTokens
	ct := resp.Usage.OutputTokens
	tt := pt + ct
	// Model-specific pricing: сначала модель из ответа провайдера,
	// затем provider default. Пустая строка попадала в fallback pricing
	// независимо от модели (баг симметричный PR a147978).
	model := resp.Model
	if model == "" {
		model = p.DefaultModel()
	}
	c := calculateProviderCost(anthropicPricing, anthropicFallbackPricing, model, pt, ct)
	return pt, ct, tt, c, nil
}

func (p *AnthropicProvider) StreamFormat() StreamFormat { return StreamSSE }
func (p *AnthropicProvider) DefaultModel() string      { return "claude-3-5-sonnet-20241022" }

func (p *AnthropicProvider) SupportedModels() []string {
	return []string{
		"claude-3-5-sonnet-20241022",
		"claude-3-5-haiku-20241022",
		"claude-3-opus-20240229",
		"claude-3-sonnet-20240229",
		"claude-3-haiku-20240307",
	}
}

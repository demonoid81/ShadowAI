package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

var openAIPricing = map[string][2]float64{
	"gpt-4o":        {5.0 / 1_000_000, 15.0 / 1_000_000},
	"gpt-4o-mini":   {0.15 / 1_000_000, 0.60 / 1_000_000},
	"gpt-3.5-turbo": {0.50 / 1_000_000, 1.50 / 1_000_000},
	"gpt-4-turbo":   {10.0 / 1_000_000, 30.0 / 1_000_000},
	"gpt-4":         {30.0 / 1_000_000, 60.0 / 1_000_000},
	"o1":            {15.0 / 1_000_000, 60.0 / 1_000_000},
	"o1-mini":       {3.0 / 1_000_000, 12.0 / 1_000_000},
}

var openAIFallbackPricing = [2]float64{0.15 / 1_000_000, 0.60 / 1_000_000}

// OpenAIProvider handles OpenAI API requests.
type OpenAIProvider struct {
	base *OpenAICompatProvider
}

// NewOpenAIProvider creates a new OpenAI provider.
func NewOpenAIProvider(apiKey string) *OpenAIProvider {
	return &OpenAIProvider{
		base: &OpenAICompatProvider{
			ProviderName: "openai",
			BaseURL:      "https://api.openai.com/v1/chat/completions",
			APIKey:       apiKey,
			Models:       []string{"gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo", "gpt-4-turbo", "gpt-4", "o1", "o1-mini"},
			Default:      "gpt-4o-mini",
			Pricing:      openAIPricing,
			Fallback:     openAIFallbackPricing,
			// OpenAI имеет документированную поддержку stream_options.include_usage=true,
			// который возвращает финальный chunk с usage перед [DONE].
			// Без этого флага в streaming нет accounting — закрываем баг budget-обхода.
			InjectIncludeUsage: true,
		},
	}
}

func (p *OpenAIProvider) Name() string                    { return p.base.Name() }
func (p *OpenAIProvider) StreamFormat() StreamFormat       { return p.base.StreamFormat() }
func (p *OpenAIProvider) DefaultModel() string            { return p.base.DefaultModel() }
func (p *OpenAIProvider) SupportedModels() []string       { return p.base.SupportedModels() }

func (p *OpenAIProvider) BuildRequest(ctx context.Context, body []byte, model string) (*http.Request, error) {
	return p.base.BuildRequest(ctx, body, model)
}

func (p *OpenAIProvider) ParseResponse(body []byte) (promptTokens, completionTokens, totalTokens int, cost float64, err error) {
	var resp struct {
		Model string `json:"model"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("openai: parse response: %w", err)
	}
	pt := resp.Usage.PromptTokens
	ct := resp.Usage.CompletionTokens
	tt := resp.Usage.TotalTokens
	c := calculateProviderCost(openAIPricing, openAIFallbackPricing, resp.Model, pt, ct)
	return pt, ct, tt, c, nil
}

// ParseStreamUsage делегирует в общий OpenAI-compat парсер.
func (p *OpenAIProvider) ParseStreamUsage(body []byte, requestModel string) (StreamUsage, error) {
	return p.base.ParseStreamUsage(body, requestModel)
}

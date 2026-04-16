package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// openAIChatResponse is the common response structure for OpenAI-compatible APIs.
type openAIChatResponse struct {
	// Model возвращается провайдером в финальном non-stream ответе и
	// является источником истины для model-specific pricing lookup.
	// Ранее cost считался с пустым model, что всегда попадало в fallback
	// pricing — для Mistral/Groq/OpenRouter это было материально неточно.
	Model string `json:"model,omitempty"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// OpenAICompatProvider is the base type for all OpenAI-compatible providers.
type OpenAICompatProvider struct {
	ProviderName string
	BaseURL      string
	APIKey       string
	AuthHeader   string // "Authorization" by default
	AuthPrefix   string // "Bearer " by default
	ExtraHeaders map[string]string
	Models       []string
	Default      string
	Pricing      map[string][2]float64
	Fallback     [2]float64
	// InjectIncludeUsage=true заставляет BuildRequest добавлять
	// stream_options.include_usage=true в streaming-запросы. Включать
	// только для провайдеров с документированной поддержкой (OpenAI).
	// Для Groq/Mistral/OpenRouter флаг оставлять false — best-effort
	// parsing без mutation запроса.
	InjectIncludeUsage bool
}

func (p *OpenAICompatProvider) Name() string {
	return p.ProviderName
}

func (p *OpenAICompatProvider) BuildRequest(ctx context.Context, body []byte, model string) (*http.Request, error) {
	// Если провайдер требует include_usage для stream accounting, inject'им его.
	// Работает только для streaming-запросов (body.stream=true).
	if p.InjectIncludeUsage {
		patched, patchErr := patchOpenAIStreamOptions(body, true)
		if patchErr == nil {
			body = patched
		}
		// patchErr != nil → тихо продолжаем с исходным body. Accounting
		// деградирует до Found=false, но отказ запроса был бы хуже.
	}
	req, err := http.NewRequestWithContext(ctx, "POST", p.BaseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: build request: %w", p.ProviderName, err)
	}
	req.Header.Set("Content-Type", "application/json")

	authHeader := p.AuthHeader
	if authHeader == "" {
		authHeader = "Authorization"
	}
	authPrefix := p.AuthPrefix
	if authPrefix == "" {
		authPrefix = "Bearer "
	}
	if p.APIKey != "" {
		req.Header.Set(authHeader, authPrefix+p.APIKey)
	}

	for k, v := range p.ExtraHeaders {
		req.Header.Set(k, v)
	}

	return req, nil
}

func (p *OpenAICompatProvider) ParseResponse(body []byte) (promptTokens, completionTokens, totalTokens int, cost float64, err error) {
	var resp openAIChatResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("%s: parse response: %w", p.ProviderName, err)
	}
	promptTokens = resp.Usage.PromptTokens
	completionTokens = resp.Usage.CompletionTokens
	totalTokens = resp.Usage.TotalTokens
	// Model-specific pricing: сначала модель из ответа провайдера,
	// затем provider default. Пустая строка попадает в fallback pricing,
	// что для Mistral/Groq/OpenRouter было источником материальных
	// неточностей в billing.
	model := resp.Model
	if model == "" {
		model = p.Default
	}
	cost = calculateProviderCost(p.Pricing, p.Fallback, model, promptTokens, completionTokens)
	return
}

func (p *OpenAICompatProvider) StreamFormat() StreamFormat {
	return StreamSSE
}

func (p *OpenAICompatProvider) DefaultModel() string {
	return p.Default
}

func (p *OpenAICompatProvider) SupportedModels() []string {
	return p.Models
}

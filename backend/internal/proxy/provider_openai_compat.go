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
}

func (p *OpenAICompatProvider) Name() string {
	return p.ProviderName
}

func (p *OpenAICompatProvider) BuildRequest(ctx context.Context, body []byte, model string) (*http.Request, error) {
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
	cost = calculateProviderCost(p.Pricing, p.Fallback, "", promptTokens, completionTokens)
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

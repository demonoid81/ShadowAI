package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

var geminiPricing = map[string][2]float64{
	"gemini-1.5-pro":   {3.5 / 1_000_000, 10.5 / 1_000_000},
	"gemini-1.5-flash": {0.075 / 1_000_000, 0.30 / 1_000_000},
	"gemini-pro":       {0.50 / 1_000_000, 1.50 / 1_000_000},
}

var geminiFallbackPricing = [2]float64{0.50 / 1_000_000, 1.50 / 1_000_000}

type geminiResponse struct {
	// ModelVersion возвращается Gemini в non-stream ответе (аналогично
	// полю modelVersion в stream chunks). Используется для pricing.
	// До фикса — передавалось "" в calculateProviderCost, все запросы
	// падали на fallback pricing (баг симметричный PR a147978).
	ModelVersion  string `json:"modelVersion,omitempty"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
		TotalTokenCount      int `json:"totalTokenCount"`
	} `json:"usageMetadata"`
}

// GeminiProvider handles Google Gemini generateContent API requests.
type GeminiProvider struct {
	apiKey string
}

// NewGeminiProvider creates a new Google Gemini provider.
func NewGeminiProvider(apiKey string) *GeminiProvider {
	return &GeminiProvider{apiKey: apiKey}
}

func (p *GeminiProvider) Name() string { return "gemini" }

func (p *GeminiProvider) BuildRequest(ctx context.Context, body []byte, model string) (*http.Request, error) {
	if model == "" {
		model = p.DefaultModel()
	}
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, p.apiKey)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("gemini: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (p *GeminiProvider) ParseResponse(body []byte) (promptTokens, completionTokens, totalTokens int, cost float64, err error) {
	var resp geminiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("gemini: parse response: %w", err)
	}
	pt := resp.UsageMetadata.PromptTokenCount
	ct := resp.UsageMetadata.CandidatesTokenCount
	tt := resp.UsageMetadata.TotalTokenCount
	if tt == 0 {
		tt = pt + ct
	}
	// Model-specific pricing: modelVersion из ответа → fallback на
	// provider default. Пустая строка раньше давала fallback pricing
	// на каждый запрос.
	model := resp.ModelVersion
	if model == "" {
		model = p.DefaultModel()
	}
	c := calculateProviderCost(geminiPricing, geminiFallbackPricing, model, pt, ct)
	return pt, ct, tt, c, nil
}

func (p *GeminiProvider) StreamFormat() StreamFormat { return StreamSSE }
func (p *GeminiProvider) DefaultModel() string       { return "gemini-1.5-flash" }

func (p *GeminiProvider) SupportedModels() []string {
	return []string{"gemini-1.5-pro", "gemini-1.5-flash", "gemini-pro"}
}

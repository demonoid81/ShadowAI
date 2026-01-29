package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type ollamaResponse struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
	PromptEvalCount int `json:"prompt_eval_count"`
	EvalCount       int `json:"eval_count"`
}

// OllamaProvider handles Ollama API requests (local, NDJSON streaming).
type OllamaProvider struct {
	baseURL string
}

// NewOllamaProvider creates a new Ollama provider.
func NewOllamaProvider(baseURL string) *OllamaProvider {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return &OllamaProvider{baseURL: baseURL}
}

func (p *OllamaProvider) Name() string { return "ollama" }

func (p *OllamaProvider) BuildRequest(ctx context.Context, body []byte, model string) (*http.Request, error) {
	url := p.baseURL + "/api/chat"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ollama: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (p *OllamaProvider) ParseResponse(body []byte) (promptTokens, completionTokens, totalTokens int, cost float64, err error) {
	var resp ollamaResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("ollama: parse response: %w", err)
	}
	pt := resp.PromptEvalCount
	ct := resp.EvalCount
	tt := pt + ct
	// Ollama is free (local)
	return pt, ct, tt, 0, nil
}

func (p *OllamaProvider) StreamFormat() StreamFormat { return StreamNDJSON }
func (p *OllamaProvider) DefaultModel() string       { return "llama3.1" }

func (p *OllamaProvider) SupportedModels() []string {
	return []string{"llama3.1", "llama3", "mistral", "codellama", "gemma2", "phi3"}
}

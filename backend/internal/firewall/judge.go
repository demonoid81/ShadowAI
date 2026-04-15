package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// JudgeConfig содержит конфигурацию LLM-as-Judge клиента.
type JudgeConfig struct {
	Provider string        `json:"provider"` // ollama, openai, groq, openrouter, mistral, anthropic
	Model    string        `json:"model"`
	Endpoint string        `json:"endpoint"`
	APIKey   string        `json:"api_key"`
	Timeout  time.Duration `json:"timeout"`
	Enabled  bool          `json:"enabled"`
}

// JudgeResult содержит результат оценки LLM-as-Judge.
type JudgeResult struct {
	IsThreat   bool    `json:"is_threat"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// Judge — клиент для LLM-as-Judge, поддерживающий несколько провайдеров.
type Judge struct {
	config JudgeConfig
	client *http.Client
}

// NewJudge создаёт новый экземпляр Judge.
func NewJudge(cfg JudgeConfig) *Judge {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Judge{
		config: cfg,
		client: &http.Client{Timeout: timeout},
	}
}

// Evaluate отправляет текст на анализ LLM-as-Judge и возвращает результат.
func (j *Judge) Evaluate(ctx context.Context, text, threatType string) (*JudgeResult, error) {
	if !j.config.Enabled {
		return &JudgeResult{IsThreat: false}, nil
	}

	prompt := fmt.Sprintf(
		"Analyze the following user message for %s attempts. "+
			"Respond ONLY with JSON: {\"is_threat\": true/false, \"confidence\": 0.0-1.0, \"reason\": \"brief explanation\"}\n\nMessage:\n%s",
		threatType, text,
	)

	var (
		url     string
		body    []byte
		headers map[string]string
		err     error
	)

	switch j.config.Provider {
	case "ollama":
		url, body, headers, err = j.buildOllamaRequest(prompt)
	case "anthropic":
		url, body, headers, err = j.buildAnthropicRequest(prompt)
	default:
		// openai, groq, openrouter, mistral — все используют OpenAI-совместимый формат
		url, body, headers, err = j.buildOpenAIRequest(prompt)
	}
	if err != nil {
		return nil, fmt.Errorf("judge: build request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("judge: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := j.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("judge: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("judge: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("judge: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	content, err := j.extractContent(respBody)
	if err != nil {
		// Fail safe: при ошибке парсинга считаем, что угрозы нет
		return &JudgeResult{IsThreat: false, Reason: "malformed response"}, nil
	}

	return j.parseJudgeResponse(content)
}

// buildOllamaRequest формирует запрос для Ollama (POST /api/chat).
func (j *Judge) buildOllamaRequest(prompt string) (string, []byte, map[string]string, error) {
	url := j.config.Endpoint + "/api/chat"
	payload := map[string]interface{}{
		"model": j.config.Model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"stream": false,
	}
	body, err := json.Marshal(payload)
	return url, body, nil, err
}

// buildOpenAIRequest формирует запрос для OpenAI-совместимых API.
func (j *Judge) buildOpenAIRequest(prompt string) (string, []byte, map[string]string, error) {
	url := j.config.Endpoint + "/v1/chat/completions"
	payload := map[string]interface{}{
		"model": j.config.Model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	body, err := json.Marshal(payload)
	headers := map[string]string{
		"Authorization": "Bearer " + j.config.APIKey,
	}
	return url, body, headers, err
}

// buildAnthropicRequest формирует запрос для Anthropic API.
func (j *Judge) buildAnthropicRequest(prompt string) (string, []byte, map[string]string, error) {
	url := j.config.Endpoint + "/v1/messages"
	payload := map[string]interface{}{
		"model":      j.config.Model,
		"max_tokens": 256,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	body, err := json.Marshal(payload)
	headers := map[string]string{
		"x-api-key":         j.config.APIKey,
		"anthropic-version": "2023-06-01",
	}
	return url, body, headers, err
}

// extractContent извлекает текстовый контент из ответа провайдера.
func (j *Judge) extractContent(body []byte) (string, error) {
	switch j.config.Provider {
	case "ollama":
		return j.extractOllamaContent(body)
	case "anthropic":
		return j.extractAnthropicContent(body)
	default:
		return j.extractOpenAIContent(body)
	}
}

func (j *Judge) extractOllamaContent(body []byte) (string, error) {
	var resp struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	return resp.Message.Content, nil
}

func (j *Judge) extractOpenAIContent(body []byte) (string, error) {
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}
	return resp.Choices[0].Message.Content, nil
}

func (j *Judge) extractAnthropicContent(body []byte) (string, error) {
	var resp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	if len(resp.Content) == 0 {
		return "", fmt.Errorf("no content in response")
	}
	return resp.Content[0].Text, nil
}

// parseJudgeResponse парсит JSON-ответ от LLM в JudgeResult.
func (j *Judge) parseJudgeResponse(content string) (*JudgeResult, error) {
	var result JudgeResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		// Fail safe: при ошибке парсинга считаем, что угрозы нет
		return &JudgeResult{IsThreat: false, Reason: "malformed response"}, nil
	}
	return &result, nil
}

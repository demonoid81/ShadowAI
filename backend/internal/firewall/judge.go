package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/shadowai/backend/internal/metrics"
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
//
// Observability contract (PR-2):
//   - Каждый enabled Evaluate() → RecordJudgeRequest (denominator).
//   - Transport/HTTP/build errors → RecordJudgeFail + return error.
//   - context.DeadlineExceeded / client timeout → RecordJudgeTimeout.
//   - 200 OK но unparsable → RecordJudgeMalformed + soft-allow fallback.
//   - Успешный soft-allow путь (fallback) → RecordJudgeFallback.
//   - Latency histogram на всех путях кроме transport-level ошибок.
//
// Fallback path КРИТИЧЕН для security: когда judge возвращает
// "not threat" из-за malformed response, это визуальное решение
// не блокировать. Метрика JudgeFallback делает этот case видимым.
func (j *Judge) Evaluate(ctx context.Context, text, threatType string) (*JudgeResult, error) {
	if !j.config.Enabled {
		return &JudgeResult{IsThreat: false}, nil
	}

	metrics.RecordJudgeRequest(j.config.Provider, threatType)
	start := time.Now()

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
		metrics.RecordJudgeFail(j.config.Provider, threatType)
		return nil, fmt.Errorf("judge: build request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		metrics.RecordJudgeFail(j.config.Provider, threatType)
		return nil, fmt.Errorf("judge: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := j.client.Do(req)
	if err != nil {
		// Различаем timeout (отдельный счётчик для alerting) и transport errors.
		if isTimeoutError(err) {
			metrics.RecordJudgeTimeout(j.config.Provider, threatType)
		} else {
			metrics.RecordJudgeFail(j.config.Provider, threatType)
		}
		return nil, fmt.Errorf("judge: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		metrics.RecordJudgeFail(j.config.Provider, threatType)
		return nil, fmt.Errorf("judge: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		metrics.RecordJudgeFail(j.config.Provider, threatType)
		return nil, fmt.Errorf("judge: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	// До этого момента latency осмысленна (получили полный body, успех на транспорте).
	metrics.ObserveJudgeLatency(j.config.Provider, threatType, time.Since(start).Seconds())

	content, err := j.extractContent(respBody)
	if err != nil {
		// Provider-level schema mismatch (JSON valid, но без expected fields).
		// Silent degradation если не логгировать — поэтому:
		//   1. RecordJudgeMalformed — счётчик для monitoring.
		//   2. RecordJudgeFallback — видимое "решение не блокировать".
		//   3. log warning — человек прочитает при инциденте.
		metrics.RecordJudgeMalformed(j.config.Provider, threatType)
		metrics.RecordJudgeFallback(j.config.Provider, threatType)
		log.Printf("judge: malformed response from provider=%q threat_type=%q: %v — falling back to IsThreat=false",
			j.config.Provider, threatType, err)
		return &JudgeResult{IsThreat: false, Reason: "malformed response"}, nil
	}

	return j.parseJudgeResponse(content, threatType)
}

// isTimeoutError распознаёт таймаут http.Client.Do (не transport refused).
// Использует context deadline, net.Error Timeout(), и os.IsTimeout.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
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
//
// Второй potential malformed path (после extractContent): provider
// вернул "content" с текстом, но текст не является валидным JSON
// ожидаемой схемы. Метрика та же — видимое решение не блокировать.
func (j *Judge) parseJudgeResponse(content, threatType string) (*JudgeResult, error) {
	var result JudgeResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		metrics.RecordJudgeMalformed(j.config.Provider, threatType)
		metrics.RecordJudgeFallback(j.config.Provider, threatType)
		log.Printf("judge: malformed JSON payload from provider=%q threat_type=%q: %v — falling back to IsThreat=false",
			j.config.Provider, threatType, err)
		return &JudgeResult{IsThreat: false, Reason: "malformed response"}, nil
	}
	return &result, nil
}

// Config возвращает текущую конфигурацию judge (read-only) для status API.
// APIKey не возвращается, чтобы не утечь через /proxy/firewall/status.
func (j *Judge) Config() JudgeConfig {
	if j == nil {
		return JudgeConfig{}
	}
	sanitized := j.config
	sanitized.APIKey = ""
	return sanitized
}

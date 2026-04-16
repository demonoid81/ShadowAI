package proxy

import "encoding/json"

// Внутренние DTO для парсинга SSE-chunks. Отделены от провайдеров,
// чтобы parsers могли использоваться без циклических зависимостей
// и чтобы structs были обозримо собраны в одном месте.

// --- OpenAI-compat (OpenAI, OpenRouter, Groq, Mistral) ---

type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
	// Cost — pointer, чтобы отличить "поля нет в JSON" (nil) от
	// "explicit 0" (OpenRouter может прислать 0 для free/promotional
	// routes, и это authoritative значение, а не сигнал использовать
	// локальную pricing table).
	Cost *float64 `json:"cost,omitempty"`
}

type openAIStreamChunk struct {
	Model   string            `json:"model,omitempty"`
	Choices []json.RawMessage `json:"choices"`
	Usage   *openAIUsage      `json:"usage,omitempty"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// --- Anthropic (Messages API streaming) ---

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens,omitempty"`
	OutputTokens int `json:"output_tokens,omitempty"`
}

// anthropicStreamEvent — union-like DTO для всех типов Anthropic SSE events.
// Type и подтипы fields заполняются выборочно в зависимости от event'а:
//   - "message_start":        Message.Usage.InputTokens — prompt side
//   - "message_delta":        Usage.OutputTokens — cumulative completion count
//   - "content_block_delta":  только delta текста, usage игнорируется
//   - "ping"/"message_stop":  без usage
type anthropicStreamEvent struct {
	Type    string `json:"type"`
	Message *struct {
		Model string         `json:"model,omitempty"`
		Usage anthropicUsage `json:"usage"`
	} `json:"message,omitempty"`
	Usage *anthropicUsage `json:"usage,omitempty"`
}

// --- Gemini (streamGenerateContent?alt=sse) ---

type geminiUsage struct {
	PromptTokenCount     int `json:"promptTokenCount,omitempty"`
	CandidatesTokenCount int `json:"candidatesTokenCount,omitempty"`
	TotalTokenCount      int `json:"totalTokenCount,omitempty"`
}

type geminiStreamChunk struct {
	UsageMetadata *geminiUsage `json:"usageMetadata,omitempty"`
	ModelVersion  string       `json:"modelVersion,omitempty"`
}

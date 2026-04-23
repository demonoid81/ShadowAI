package streaming

// Canonical streaming fixtures для round-trip и decoder correctness
// тестов. Все fixtures — byte literals, чтобы tests не зависели от
// сетевых provider'ов и работали на CI без Docker.
//
// Формат: переменные с суффиксом Fixture (полный stream bytes) +
// expectedXxx (ожидаемая последовательность событий, для decoder
// тестов).

// fixtureOpenAINormal — стандартный OpenAI Chat streaming с
// 3 delta frame'ами и финальным [DONE]. Без usage (include_usage=false
// или не-supporting client).
var fixtureOpenAINormal = []byte(
	`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":" world"},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n" +
		`data: [DONE]` + "\n\n")

// fixtureOpenAIWithUsage — OpenAI с include_usage=true. Финальный
// frame содержит usage и пустой choices.
var fixtureOpenAIWithUsage = []byte(
	`data: {"id":"c-2","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Hi"}}]}` + "\n\n" +
		`data: {"id":"c-2","model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n" +
		`data: {"id":"c-2","model":"gpt-4o","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}` + "\n\n" +
		`data: [DONE]` + "\n\n")

// fixtureAnthropicNamed — Anthropic SSE с named events.
var fixtureAnthropicNamed = []byte(
	`event: message_start` + "\n" +
		`data: {"type":"message_start","message":{"id":"msg-1","model":"claude-3-5-sonnet","usage":{"input_tokens":10,"output_tokens":0}}}` + "\n\n" +
		`event: content_block_start` + "\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
		`event: ping` + "\n" +
		`data: {"type":"ping"}` + "\n\n" +
		`event: content_block_delta` + "\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}` + "\n\n" +
		`event: content_block_delta` + "\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" there"}}` + "\n\n" +
		`event: content_block_stop` + "\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		`event: message_delta` + "\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":10,"output_tokens":2}}` + "\n\n" +
		`event: message_stop` + "\n" +
		`data: {"type":"message_stop"}` + "\n\n")

// fixtureGeminiSSE — Gemini streamGenerateContent с intermediate и
// финальным frame'ом (usageMetadata в последнем).
var fixtureGeminiSSE = []byte(
	`data: {"candidates":[{"content":{"parts":[{"text":"Hel"}],"role":"model"}}],"modelVersion":"gemini-1.5-pro"}` + "\n\n" +
		`data: {"candidates":[{"content":{"parts":[{"text":"lo"}],"role":"model"}}],"modelVersion":"gemini-1.5-pro"}` + "\n\n" +
		`data: {"candidates":[{"content":{"parts":[{"text":""}],"role":"model"},"finishReason":"STOP"}],"modelVersion":"gemini-1.5-pro","usageMetadata":{"promptTokenCount":4,"candidatesTokenCount":1,"totalTokenCount":5}}` + "\n\n")

// fixtureOllamaNDJSON — Ollama /api/chat streaming: 2 delta lines
// (done=false) и финальный done=true с usage.
var fixtureOllamaNDJSON = []byte(
	`{"model":"llama3","message":{"role":"assistant","content":"Hel"},"done":false}` + "\n" +
		`{"model":"llama3","message":{"role":"assistant","content":"lo"},"done":false}` + "\n" +
		`{"model":"llama3","done":true,"done_reason":"stop","prompt_eval_count":3,"eval_count":2}` + "\n")

// fixtureOpenRouterKeepalive — OpenRouter-specific: SSE comment
// keepalive `: OPENROUTER PROCESSING` посреди потока.
var fixtureOpenRouterKeepalive = []byte(
	`: OPENROUTER PROCESSING` + "\n\n" +
		`data: {"id":"or-1","model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hi"}}]}` + "\n\n" +
		`: OPENROUTER PROCESSING` + "\n\n" +
		`data: {"id":"or-1","model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n" +
		`data: [DONE]` + "\n\n")

// fixtureOpenAIMalformed — frame с невалидным JSON. Decoder должен
// эмитить EventUnknownChunk и не крашиться.
var fixtureOpenAIMalformed = []byte(
	`data: {"id":"c-3","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"ok"}}]}` + "\n\n" +
		`data: {this is not valid json}` + "\n\n" +
		`data: [DONE]` + "\n\n")

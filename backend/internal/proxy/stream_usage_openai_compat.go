package proxy

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
)

// patchOpenAIStreamOptions мержит stream_options.include_usage=true в
// body запроса. Merge, не overwrite: если клиент уже передал другие
// stream_options, они сохраняются. Если клиент передал include_usage=false
// (явный opt-out accounting), мы всё равно overwrite'им в true и логируем
// WARNING — наша budget/security модель важнее клиентского предпочтения.
//
// Контракт:
//   - body не valid JSON → возвращает исходный body без изменений
//     и nil error (fail-safe для malformed requests, они всё равно
//     упадут на upstream).
//   - stream=false или отсутствует → не трогаем body (include_usage
//     актуален только для streaming).
//   - stream_options отсутствует → создаём { "include_usage": true }.
//   - stream_options.include_usage=true уже стоит → no-op.
//   - stream_options.include_usage=false → overwrite на true + WARNING.
//
// Используется только когда p.InjectIncludeUsage=true (т.е. OpenAI).
func patchOpenAIStreamOptions(body []byte, includeUsage bool) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		// Malformed JSON — не наша забота, upstream отдаст 400.
		return body, nil
	}

	// Только streaming-запросы нуждаются в include_usage.
	streamVal, hasStream := raw["stream"]
	isStream := false
	if s, ok := streamVal.(bool); ok {
		isStream = s
	}
	if !hasStream || !isStream {
		return body, nil
	}

	opts, _ := raw["stream_options"].(map[string]any)
	if opts == nil {
		opts = make(map[string]any)
	}

	if existing, ok := opts["include_usage"].(bool); ok {
		if existing == includeUsage {
			return body, nil // no-op
		}
		// Overwrite с WARNING: клиент явно отказался от accounting,
		// но мы не можем согласиться без потери visibility.
		log.Printf("openai-compat: overriding client-supplied stream_options.include_usage=%v → %v (accounting required)",
			existing, includeUsage)
	}
	opts["include_usage"] = includeUsage
	raw["stream_options"] = opts

	out, err := json.Marshal(raw)
	if err != nil {
		return body, nil // fail-safe
	}
	return out, nil
}

// sseDoneMarker — OpenAI-compat terminator, приходит как `data: [DONE]`.
// Не JSON, пропускаем при парсинге.
var sseDoneMarker = []byte("[DONE]")

// parseOpenAICompatStreamUsage — общий парсер для OpenAI и всех
// OpenAI-compatible провайдеров (OpenRouter/Groq/Mistral). Ищет
// последний non-nil usage-объект в SSE-потоке.
//
// Стратегия:
//  1. Идём по SSE events через walkSSE.
//  2. Пропускаем [DONE] sentinel и comments.
//  3. Парсим data как openAIStreamChunk; интересует Usage и Model.
//  4. Усваиваем last seen non-nil usage.
//  5. Если в финальном usage есть Cost (OpenRouter usage.cost) — берём его
//     как source of truth. Иначе считаем по pricing table с resp.Model,
//     fallback на requestModel.
//
// Found=true требует наличия reasonable usage: хотя бы prompt_tokens
// или completion_tokens > 0, либо явный non-zero cost.
func parseOpenAICompatStreamUsage(
	body []byte,
	requestModel string,
	pricing map[string][2]float64,
	fallback [2]float64,
) (StreamUsage, error) {
	var (
		lastUsage *openAIUsage
		lastModel string
	)

	err := walkSSE(body, func(e sseEvent) error {
		// [DONE] — не JSON, пропускаем.
		if bytes.Equal(bytes.TrimSpace(e.Data), sseDoneMarker) {
			return nil
		}
		// Empty data: игнорируем без ошибки.
		if len(bytes.TrimSpace(e.Data)) == 0 {
			return nil
		}

		var chunk openAIStreamChunk
		if err := json.Unmarshal(e.Data, &chunk); err != nil {
			// Неразобранный chunk (например, mid-stream error от OpenRouter
			// с нестандартной схемой) — не ломаем поток, просто пропускаем.
			return nil
		}
		if chunk.Usage != nil {
			lastUsage = chunk.Usage
		}
		// Model обычно присутствует почти во всех chunk'ах; берём последний
		// известный (некоторые провайдеры опускают его в финальном frame).
		if strings.TrimSpace(chunk.Model) != "" {
			lastModel = chunk.Model
		}
		return nil
	})
	if err != nil {
		return StreamUsage{}, err
	}

	if lastUsage == nil {
		return StreamUsage{Found: false}, nil
	}

	// Model для pricing lookup: приоритет у response.model → requestModel.
	pricingModel := lastModel
	if pricingModel == "" {
		pricingModel = requestModel
	}

	usage := StreamUsage{
		PromptTokens:     lastUsage.PromptTokens,
		CompletionTokens: lastUsage.CompletionTokens,
		TotalTokens:      lastUsage.TotalTokens,
		Model:            lastModel,
	}

	// OpenRouter включает usage.cost в финальный chunk. Если он есть —
	// это authoritative billing от провайдера, использовать как есть.
	// Иначе считаем локально по pricing table.
	if lastUsage.Cost > 0 {
		usage.CostUSD = lastUsage.Cost
	} else {
		usage.CostUSD = calculateProviderCost(pricing, fallback, pricingModel,
			lastUsage.PromptTokens, lastUsage.CompletionTokens)
	}

	// Found=true требует хотя бы какого-то content'а: токенов или явного cost.
	usage.Found = lastUsage.PromptTokens > 0 ||
		lastUsage.CompletionTokens > 0 ||
		lastUsage.TotalTokens > 0 ||
		lastUsage.Cost > 0
	return usage, nil
}

// ParseStreamUsage реализует StreamUsageProvider для всех OpenAI-compatible
// провайдеров. OpenAI и OpenRouter получат аккуратное usage если клиент
// или inject запросили include_usage. Для Groq/Mistral accounting
// best-effort: Found=false допустим.
func (p *OpenAICompatProvider) ParseStreamUsage(body []byte, requestModel string) (StreamUsage, error) {
	return parseOpenAICompatStreamUsage(body, requestModel, p.Pricing, p.Fallback)
}

package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// parseGeminiStreamUsage парсит Gemini streamGenerateContent?alt=sse поток.
//
// Gemini контракт (https://ai.google.dev/api/generate-content):
//   - Body — SSE data-only (без named events), каждый chunk — одна
//     GenerateContentResponse в data-frame.
//   - usageMetadata — output-only поле; docs НЕ фиксируют, в каком именно
//     chunk (промежуточном или финальном) оно придёт с полными counts.
//     В наблюдаемой практике обычно в финальном, но не всегда.
//   - modelVersion возвращается в chunks, используется для pricing lookup.
//
// Стратегия: берём last non-empty usageMetadata. "Non-empty" = хотя бы
// одно из token count полей > 0 (иначе это stub от промежуточного frame).
//
// Контракт парсера:
//   - Found=true: получили non-empty usageMetadata.
//   - Malformed JSON → parser error (per StreamUsageProvider contract).
func parseGeminiStreamUsage(body []byte, requestModel string) (StreamUsage, error) {
	var (
		lastUsage *geminiUsage
		lastModel string
	)

	err := walkSSE(body, func(e sseEvent) error {
		if len(bytes.TrimSpace(e.Data)) == 0 {
			return nil
		}

		var chunk geminiStreamChunk
		if err := json.Unmarshal(e.Data, &chunk); err != nil {
			return fmt.Errorf("gemini: malformed SSE frame: %w", err)
		}

		// Принимаем usageMetadata только если в нём есть реальные counts.
		// Пустой объект usageMetadata:{} в промежуточном chunk'е не
		// должен перекрывать последующий non-empty.
		if chunk.UsageMetadata != nil && isGeminiUsageNonEmpty(chunk.UsageMetadata) {
			lastUsage = chunk.UsageMetadata
		}
		if chunk.ModelVersion != "" {
			lastModel = chunk.ModelVersion
		}
		return nil
	})
	if err != nil {
		return StreamUsage{}, err
	}

	if lastUsage == nil {
		return StreamUsage{Found: false}, nil
	}

	pricingModel := lastModel
	if pricingModel == "" {
		pricingModel = requestModel
	}

	pt := lastUsage.PromptTokenCount
	ct := lastUsage.CandidatesTokenCount
	tt := lastUsage.TotalTokenCount
	if tt == 0 {
		tt = pt + ct
	}

	cost := calculateProviderCost(geminiPricing, geminiFallbackPricing,
		pricingModel, pt, ct)

	return StreamUsage{
		PromptTokens:     pt,
		CompletionTokens: ct,
		TotalTokens:      tt,
		CostUSD:          cost,
		Model:            lastModel,
		Found:            true,
	}, nil
}

func isGeminiUsageNonEmpty(u *geminiUsage) bool {
	return u.PromptTokenCount > 0 ||
		u.CandidatesTokenCount > 0 ||
		u.TotalTokenCount > 0
}

// ParseStreamUsage реализует StreamUsageProvider для Gemini.
func (p *GeminiProvider) ParseStreamUsage(body []byte, requestModel string) (StreamUsage, error) {
	return parseGeminiStreamUsage(body, requestModel)
}

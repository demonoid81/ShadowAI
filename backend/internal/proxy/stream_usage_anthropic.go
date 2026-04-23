package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// parseAnthropicStreamUsage парсит Anthropic Messages API SSE-поток.
//
// Named event contract (https://docs.anthropic.com/en/api/messages-streaming):
//   - message_start: message.usage.input_tokens — prompt side (final сразу)
//   - content_block_delta: текст, без usage
//   - message_delta: usage.output_tokens — CUMULATIVE completion count.
//     Последнее значение в финальном message_delta = итог; если stream
//     прервался, берём last seen (не суммируем).
//   - ping: keepalive, игнорируется на уровне walkSSE (data: {} — валидный JSON
//     без полей, не обновляет state).
//   - message_stop: завершение stream.
//
// Контракт парсера:
//   - Found=true: получили input_tokens ИЛИ output_tokens > 0.
//   - Malformed JSON в data: parser error (per StreamUsageProvider contract).
//   - Неизвестные event types игнорируются.
func parseAnthropicStreamUsage(body []byte, requestModel string) (StreamUsage, error) {
	var (
		promptTokens     int
		completionTokens int
		respModel        string
		haveInput        bool
		haveOutput       bool
		// PR-F7.4: отслеживаем message_stop, чтобы установить Partial=true
		// для interrupted stream'ов. Если message_delta seen (haveOutput)
		// но message_stop NOT seen → stream завершился до финального
		// терминирующего сигнала → Partial=true.
		sawMessageStop bool
	)

	err := walkSSE(body, func(e sseEvent) error {
		// Empty data пропускаем без ошибки.
		if len(bytes.TrimSpace(e.Data)) == 0 {
			return nil
		}

		var ev anthropicStreamEvent
		if err := json.Unmarshal(e.Data, &ev); err != nil {
			return fmt.Errorf("anthropic: malformed SSE frame (event=%q): %w", e.Event, err)
		}

		// Event приоритет: берём sseEvent.Event (field "event:"), если он
		// задан. Fallback на ev.Type — Anthropic дублирует тип события в
		// data payload, но named event — primary source.
		kind := e.Event
		if kind == "" {
			kind = ev.Type
		}

		switch kind {
		case "message_start":
			if ev.Message != nil {
				promptTokens = ev.Message.Usage.InputTokens
				if promptTokens > 0 {
					haveInput = true
				}
				if ev.Message.Model != "" {
					respModel = ev.Message.Model
				}
				// Anthropic иногда шлёт и output_tokens=0 на message_start —
				// безопасно игнорировать до первого message_delta.
			}
		case "message_delta":
			// CUMULATIVE: replace, не add.
			if ev.Usage != nil {
				completionTokens = ev.Usage.OutputTokens
				if completionTokens > 0 {
					haveOutput = true
				}
			}
		case "message_stop":
			// PR-F7.4: финальный терминирующий сигнал Anthropic stream'а.
			// Presence означает stream завершился нормально — usage НЕ partial.
			sawMessageStop = true
		case "ping", "content_block_start", "content_block_delta",
			"content_block_stop":
			// Игнорируем — usage-данных не несут.
		default:
			// Unknown event type — не ошибка (forward compat с новыми типами событий).
		}
		return nil
	})
	if err != nil {
		return StreamUsage{}, err
	}

	if !haveInput && !haveOutput {
		return StreamUsage{Found: false}, nil
	}

	pricingModel := respModel
	if pricingModel == "" {
		pricingModel = requestModel
	}

	totalTokens := promptTokens + completionTokens
	cost := calculateProviderCost(anthropicPricing, anthropicFallbackPricing,
		pricingModel, promptTokens, completionTokens)

	// PR-F7.4: Partial=true если usage известен, но message_stop не получен.
	// Типичный сценарий: mid-stream block после message_delta — handler уже
	// имеет output_tokens, но провайдер не успел прислать message_stop.
	partial := !sawMessageStop

	return StreamUsage{
		PromptTokens:     promptTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      totalTokens,
		CostUSD:          cost,
		Model:            respModel,
		Found:            true,
		Partial:          partial,
	}, nil
}

// ParseStreamUsage реализует StreamUsageProvider для Anthropic.
func (p *AnthropicProvider) ParseStreamUsage(body []byte, requestModel string) (StreamUsage, error) {
	return parseAnthropicStreamUsage(body, requestModel)
}

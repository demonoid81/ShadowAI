package streaming

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// OpenAICompatDecoder парсит OpenAI-compatible SSE: data-only frame'ы,
// `[DONE]` sentinel, опциональный usage в финальном chunk'е.
//
// Используется провайдерами OpenAI, Groq, Mistral, OpenRouter.
// OpenRouter дополнительно шлёт `: OPENROUTER PROCESSING` keepalive
// comment'ы — они приходят через sseFrame.Comment=true.
type OpenAICompatDecoder struct{}

// openAIChunk — минимальный JSON shape, достаточный для нормализации.
// Полный shape вариативен (function_call, tool_calls, logprobs, etc.);
// F7.1 сохраняет всё в RawBytes — парсер берёт только поля,
// необходимые для типизации Event.
type openAIChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int     `json:"prompt_tokens"`
		CompletionTokens int     `json:"completion_tokens"`
		TotalTokens      int     `json:"total_tokens"`
		Cost             float64 `json:"cost"`
	} `json:"usage"`
	Model string `json:"model"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
}

// Decode реализует streaming.Decoder.
func (OpenAICompatDecoder) Decode(ctx context.Context, r io.Reader, emit func(Event) error) error {
	return readSSEFrames(r, func(f sseFrame) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Comment-only keepalive — identity passthrough как
		// EventUnknownChunk (caller в F7.1 просто эмитит RawBytes).
		if f.Comment {
			return emit(Event{
				Type:     EventUnknownChunk,
				RawBytes: f.Raw,
			})
		}
		// Пустой frame без data — игнорируем (sseFrame уже отфильтровал
		// полностью пустые; но на всякий случай).
		if len(f.Data) == 0 {
			return nil
		}
		// [DONE] sentinel — уникальный OpenAI-compat признак окончания.
		if bytes.Equal(bytes.TrimSpace(f.Data), []byte("[DONE]")) {
			return emit(Event{
				Type:     EventMessageStop,
				RawBytes: f.Raw,
			})
		}
		// Парсим JSON chunk. Malformed JSON → unknown_chunk с
		// identity RawBytes (caller инкрементит метрику).
		var chunk openAIChunk
		if err := json.Unmarshal(f.Data, &chunk); err != nil {
			return emit(Event{
				Type:     EventUnknownChunk,
				RawBytes: f.Raw,
			})
		}
		// Provider-native error в stream'е.
		if chunk.Error != nil {
			return emit(Event{
				Type:     EventProviderError,
				Text:     chunk.Error.Message,
				RawBytes: f.Raw,
				ProviderErr: &ProviderError{
					Code:    chunk.Error.Code,
					Message: chunk.Error.Message,
					Raw:     append([]byte(nil), f.Raw...),
				},
			})
		}
		// Usage frame — может прийти отдельно или вместе с delta.
		// OpenAI (include_usage=true) обычно шлёт финальный frame с
		// пустым choices и заполненным usage. Если и delta, и usage
		// в одном frame — эмитим как usage_update (приоритет usage,
		// см. RFC Open Question §17.4: приоритет usage над stop в
		// single-frame edge case остаётся pending; для F7.1 выбираем
		// usage > stop > delta).
		if chunk.Usage != nil {
			u := &Usage{
				PromptTokens:     chunk.Usage.PromptTokens,
				CompletionTokens: chunk.Usage.CompletionTokens,
				TotalTokens:      chunk.Usage.TotalTokens,
				CostUSD:          chunk.Usage.Cost,
				Model:            chunk.Model,
			}
			return emit(Event{
				Type:     EventUsageUpdate,
				RawBytes: f.Raw,
				Usage:    u,
				Meta:     metaWithModel(chunk.Model),
			})
		}
		// finish_reason non-nil — message_stop (до финального [DONE]
		// может не быть finish_reason; порядок не гарантирован, но
		// F7.2 агрегирует correctly).
		for _, ch := range chunk.Choices {
			if ch.FinishReason != nil && *ch.FinishReason != "" {
				return emit(Event{
					Type:     EventMessageStop,
					RawBytes: f.Raw,
					Meta:     metaWithModel(chunk.Model),
				})
			}
		}
		// Regular delta text. Может быть пустой (role-only первый
		// chunk) — всё равно эмитим, чтобы round-trip остался identity.
		var text string
		for _, ch := range chunk.Choices {
			text += ch.Delta.Content
		}
		return emit(Event{
			Type:     EventDeltaText,
			Text:     text,
			RawBytes: f.Raw,
			Meta:     metaWithModel(chunk.Model),
		})
	})
}

// OpenAICompatEmitter — identity emitter для OpenAI-compat SSE.
// F7.1: Emit пишет RawBytes без re-encoding. EmitError формирует
// terminal error frame в том же SSE формате с `event: error`.
type OpenAICompatEmitter struct{}

func (OpenAICompatEmitter) Emit(ctx context.Context, w io.Writer, ev Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(ev.RawBytes) == 0 {
		// F7.1: emit без RawBytes не поддержан (sanitize active usage
		// в F7.2). Возвращаем error, чтобы caller заметил отклонение
		// от identity-first контракта.
		return fmt.Errorf("streaming: openai_compat emit without RawBytes is not supported in F7.1")
	}
	if _, err := w.Write(ev.RawBytes); err != nil {
		return err
	}
	flushIfPossible(w)
	return nil
}

// EmitError пишет SSE `event: error\ndata: {...}\n\n`. В отличие от
// data-only frame'ов OpenAI, используем именованный event type,
// чтобы клиент мог отличить streaming-level error от content.
func (OpenAICompatEmitter) EmitError(ctx context.Context, w io.Writer, code, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]string{
		"code":    code,
		"message": message,
	})
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("event: error\n")
	buf.WriteString("data: ")
	buf.Write(payload)
	buf.WriteString("\n\n")
	if _, err := w.Write(buf.Bytes()); err != nil {
		return err
	}
	flushIfPossible(w)
	return nil
}

// metaWithModel — helper, возвращает nil если model пустой, чтобы
// Meta не засорялось nil-valued ключами.
func metaWithModel(model string) map[string]string {
	if model == "" {
		return nil
	}
	return map[string]string{"model": model}
}

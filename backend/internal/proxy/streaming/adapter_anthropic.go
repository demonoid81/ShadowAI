package streaming

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// AnthropicDecoder парсит Anthropic streaming SSE: frame'ы с явным
// `event:` name'ом. Map events → normalized types:
//
//   event: message_start           → EventDeltaText (text=="", Meta.model)
//   event: content_block_start     → EventDeltaText (text=="") для round-trip identity
//   event: content_block_delta     → EventDeltaText (text = delta.text)
//   event: content_block_stop      → EventDeltaText (text=="")
//   event: message_delta           → EventUsageUpdate (usage output_tokens)
//   event: message_stop            → EventMessageStop
//   event: ping                    → EventUnknownChunk (keepalive, identity)
//   event: error                   → EventProviderError
//   остальное                       → EventUnknownChunk
//
// Rationale для "пустых" DeltaText на non-text frames: inspection
// pipeline F7.2 будет работать по sliding window over Text, и ей
// важно видеть упорядоченную последовательность; keepalive/control
// events не должны влиять на decisions, но frame identity обязана
// сохраняться для allow path.
type AnthropicDecoder struct{}

type anthropicFrame struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
	// content_block_delta:
	Delta *struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"delta,omitempty"`
	// message_start:
	Message *struct {
		ID    string `json:"id"`
		Model string `json:"model"`
		Usage *struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	} `json:"message,omitempty"`
	// message_delta: usage с cumulative output_tokens.
	Usage *struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage,omitempty"`
	// error:
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (AnthropicDecoder) Decode(ctx context.Context, r io.Reader, emit func(Event) error) error {
	var (
		// Anthropic сохраняет model из message_start, чтобы
		// проставлять в Meta на delta frame'ах.
		currentModel string
		// Для cumulative output_tokens из message_delta: parser_usage
		// превращает cumulative в delta. F7.1 не делает этого —
		// sophisticated accounting остаётся в F7.3. Здесь просто
		// эмитим значения "как пришло".
	)

	return readSSEFrames(r, func(f sseFrame) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if f.Comment {
			return emit(Event{Type: EventUnknownChunk, RawBytes: f.Raw})
		}
		if len(f.Data) == 0 && f.EventName == "" {
			return nil
		}
		var af anthropicFrame
		if err := json.Unmarshal(f.Data, &af); err != nil {
			return emit(Event{Type: EventUnknownChunk, RawBytes: f.Raw, EventName: f.EventName})
		}
		switch f.EventName {
		case "message_start":
			if af.Message != nil && af.Message.Model != "" {
				currentModel = af.Message.Model
			}
			// Если usage уже пришёл (input_tokens) — эмитим
			// usage_update.
			if af.Message != nil && af.Message.Usage != nil {
				return emit(Event{
					Type:      EventUsageUpdate,
					RawBytes:  f.Raw,
					EventName: f.EventName,
					Usage: &Usage{
						PromptTokens:     af.Message.Usage.InputTokens,
						CompletionTokens: af.Message.Usage.OutputTokens,
						Model:            currentModel,
					},
					Meta: metaWithModel(currentModel),
				})
			}
			return emit(Event{
				Type:      EventDeltaText,
				RawBytes:  f.Raw,
				EventName: f.EventName,
				Meta:      metaWithModel(currentModel),
			})
		case "content_block_start", "content_block_stop":
			return emit(Event{
				Type:      EventDeltaText,
				RawBytes:  f.Raw,
				EventName: f.EventName,
				Meta:      metaWithModel(currentModel),
			})
		case "content_block_delta":
			var text string
			if af.Delta != nil {
				text = af.Delta.Text
			}
			return emit(Event{
				Type:      EventDeltaText,
				Text:      text,
				RawBytes:  f.Raw,
				EventName: f.EventName,
				Meta:      metaWithModel(currentModel),
			})
		case "message_delta":
			if af.Usage != nil {
				return emit(Event{
					Type:      EventUsageUpdate,
					RawBytes:  f.Raw,
					EventName: f.EventName,
					Usage: &Usage{
						PromptTokens:     af.Usage.InputTokens,
						CompletionTokens: af.Usage.OutputTokens,
						Model:            currentModel,
					},
					Meta: metaWithModel(currentModel),
				})
			}
			// message_delta без usage — unknown (не нарушаем identity).
			return emit(Event{
				Type:      EventUnknownChunk,
				RawBytes:  f.Raw,
				EventName: f.EventName,
			})
		case "message_stop":
			return emit(Event{
				Type:      EventMessageStop,
				RawBytes:  f.Raw,
				EventName: f.EventName,
				Meta:      metaWithModel(currentModel),
			})
		case "ping":
			// Keepalive. Identity passthrough.
			return emit(Event{
				Type:      EventUnknownChunk,
				RawBytes:  f.Raw,
				EventName: f.EventName,
			})
		case "error":
			if af.Error != nil {
				return emit(Event{
					Type:      EventProviderError,
					Text:      af.Error.Message,
					RawBytes:  f.Raw,
					EventName: f.EventName,
					ProviderErr: &ProviderError{
						Code:    af.Error.Type,
						Message: af.Error.Message,
						Raw:     append([]byte(nil), f.Raw...),
					},
				})
			}
			return emit(Event{
				Type:      EventProviderError,
				RawBytes:  f.Raw,
				EventName: f.EventName,
			})
		default:
			return emit(Event{
				Type:      EventUnknownChunk,
				RawBytes:  f.Raw,
				EventName: f.EventName,
			})
		}
	})
}

// AnthropicEmitter — identity emitter, как и openai_compat.
type AnthropicEmitter struct{}

// EmitSanitized — PR-F7.5 stub. Anthropic wire-format sanitize re-encoding
// is not yet implemented; full support is planned for F7.6+.
// Non-delta_text events: identity. Delta_text events: identity (no re-encode).
// Callers in incremental engine treat non-nil error as transport failure.
func (e AnthropicEmitter) EmitSanitized(ctx context.Context, w io.Writer, ev Event, _ string) error {
	// Identity passthrough — sanitized text is NOT applied for Anthropic in F7.5.
	// This is safe (no silent mutation); the sanitize verdict is still recorded
	// in audit (policy_action=sanitized), but the emitted bytes are unchanged.
	// Production operators using Anthropic should set buffered mode until F7.6.
	return e.Emit(ctx, w, ev)
}

func (AnthropicEmitter) Emit(ctx context.Context, w io.Writer, ev Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(ev.RawBytes) == 0 {
		return fmt.Errorf("streaming: anthropic emit without RawBytes is not supported in F7.1")
	}
	if _, err := w.Write(ev.RawBytes); err != nil {
		return err
	}
	flushIfPossible(w)
	return nil
}

// EmitError — Anthropic SSE error event shape. Дополнительно пишем
// `event: error` чтобы клиентские SDK могли отличить его.
func (AnthropicEmitter) EmitError(ctx context.Context, w io.Writer, code, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"type": "error",
		"error": map[string]string{
			"type":    code,
			"message": message,
		},
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

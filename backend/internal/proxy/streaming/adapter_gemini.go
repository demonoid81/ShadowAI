package streaming

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// GeminiDecoder парсит Gemini streamGenerateContent SSE: data-only
// frame'ы с GenerateContentResponse JSON.
//
// Map:
//   candidates[].content.parts[].text → EventDeltaText (склейка parts)
//   usageMetadata (non-empty)         → EventUsageUpdate (параллельно)
//   finishReason non-empty             → EventMessageStop (последний)
//
// Особенность: Gemini может слать usageMetadata в intermediate
// frame'ах (не только в последнем). Round-trip всё равно identity —
// decoder просто эмитит usage_update на каждом непустом вхождении,
// агрегация в F7.3.
type GeminiDecoder struct{}

type geminiFrame struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
			Role string `json:"role"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
	UsageMetadata *struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
		TotalTokenCount      int `json:"totalTokenCount"`
	} `json:"usageMetadata"`
	ModelVersion string `json:"modelVersion"`
	Error        *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

func (GeminiDecoder) Decode(ctx context.Context, r io.Reader, emit func(Event) error) error {
	return readSSEFrames(r, func(f sseFrame) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if f.Comment {
			return emit(Event{Type: EventUnknownChunk, RawBytes: f.Raw})
		}
		if len(f.Data) == 0 {
			return nil
		}
		var gf geminiFrame
		if err := json.Unmarshal(f.Data, &gf); err != nil {
			return emit(Event{Type: EventUnknownChunk, RawBytes: f.Raw})
		}
		// Provider error.
		if gf.Error != nil {
			return emit(Event{
				Type:     EventProviderError,
				Text:     gf.Error.Message,
				RawBytes: f.Raw,
				ProviderErr: &ProviderError{
					Code:    fmt.Sprintf("%d/%s", gf.Error.Code, gf.Error.Status),
					Message: gf.Error.Message,
					Raw:     append([]byte(nil), f.Raw...),
				},
			})
		}
		// Usage: Gemini может прислать и usage, и текст в одном
		// frame'е. Приоритет (RFC §17.4) в F7.1: если есть непустой
		// usage — эмитим usage_update (Event.RawBytes всё равно
		// содержит полный frame, включая delta text, identity
		// preserved для emitter'а).
		if gf.UsageMetadata != nil && (gf.UsageMetadata.PromptTokenCount > 0 ||
			gf.UsageMetadata.CandidatesTokenCount > 0 ||
			gf.UsageMetadata.TotalTokenCount > 0) {
			return emit(Event{
				Type:     EventUsageUpdate,
				RawBytes: f.Raw,
				Usage: &Usage{
					PromptTokens:     gf.UsageMetadata.PromptTokenCount,
					CompletionTokens: gf.UsageMetadata.CandidatesTokenCount,
					TotalTokens:      gf.UsageMetadata.TotalTokenCount,
					Model:            gf.ModelVersion,
				},
				Meta: metaWithModel(gf.ModelVersion),
			})
		}
		// finishReason non-empty → message_stop (но содержимое текста
		// тоже может быть; F7.1 приоритизирует stop над delta, чтобы
		// F7.2 получила terminal signal).
		for _, c := range gf.Candidates {
			if c.FinishReason != "" {
				return emit(Event{
					Type:     EventMessageStop,
					RawBytes: f.Raw,
					Meta:     metaWithModel(gf.ModelVersion),
				})
			}
		}
		// Default: delta text — склеиваем все parts всех candidates.
		var textBuf bytes.Buffer
		for _, c := range gf.Candidates {
			for _, p := range c.Content.Parts {
				textBuf.WriteString(p.Text)
			}
		}
		return emit(Event{
			Type:     EventDeltaText,
			Text:     textBuf.String(),
			RawBytes: f.Raw,
			Meta:     metaWithModel(gf.ModelVersion),
		})
	})
}

// GeminiEmitter — identity.
type GeminiEmitter struct{}

// EmitSanitized — PR-F7.5 stub. Identity passthrough; full sanitize
// re-encoding for Gemini SSE is planned for F7.6+.
func (e GeminiEmitter) EmitSanitized(ctx context.Context, w io.Writer, ev Event, _ string) error {
	return e.Emit(ctx, w, ev)
}

func (GeminiEmitter) Emit(ctx context.Context, w io.Writer, ev Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(ev.RawBytes) == 0 {
		return fmt.Errorf("streaming: gemini emit without RawBytes is not supported in F7.1")
	}
	if _, err := w.Write(ev.RawBytes); err != nil {
		return err
	}
	flushIfPossible(w)
	return nil
}

// EmitError — Gemini streaming: шлём data-only SSE с error payload в
// формате GenerateContentResponse-compatible wrapper'а.
func (GeminiEmitter) EmitError(ctx context.Context, w io.Writer, code, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
			"status":  "UNAVAILABLE",
		},
	})
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("data: ")
	buf.Write(payload)
	buf.WriteString("\n\n")
	if _, err := w.Write(buf.Bytes()); err != nil {
		return err
	}
	flushIfPossible(w)
	return nil
}

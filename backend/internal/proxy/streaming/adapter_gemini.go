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
//
//	candidates[].content.parts[].text → EventDeltaText (склейка parts)
//	usageMetadata (non-empty)         → EventUsageUpdate (параллельно)
//	finishReason non-empty             → EventMessageStop (последний)
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
		var usage *Usage
		if gf.UsageMetadata != nil && (gf.UsageMetadata.PromptTokenCount > 0 ||
			gf.UsageMetadata.CandidatesTokenCount > 0 ||
			gf.UsageMetadata.TotalTokenCount > 0) {
			usage = &Usage{
				PromptTokens:     gf.UsageMetadata.PromptTokenCount,
				CompletionTokens: gf.UsageMetadata.CandidatesTokenCount,
				TotalTokens:      gf.UsageMetadata.TotalTokenCount,
				Model:            gf.ModelVersion,
			}
		}
		var (
			textBuf   bytes.Buffer
			hasFinish bool
		)
		for _, c := range gf.Candidates {
			if c.FinishReason != "" {
				hasFinish = true
			}
			for _, p := range c.Content.Parts {
				textBuf.WriteString(p.Text)
			}
		}
		// Text wins over usage/finishReason so response-side inspection
		// cannot be bypassed by frames that carry accounting metadata.
		if textBuf.Len() > 0 {
			return emit(Event{
				Type:     EventDeltaText,
				Text:     textBuf.String(),
				RawBytes: f.Raw,
				Usage:    usage,
				Meta:     metaWithModel(gf.ModelVersion),
			})
		}
		if usage != nil {
			return emit(Event{
				Type:     EventUsageUpdate,
				RawBytes: f.Raw,
				Usage:    usage,
				Meta:     metaWithModel(gf.ModelVersion),
			})
		}
		// finishReason non-empty → message_stop (но содержимое текста
		// уже обработано выше как delta_text, чтобы inspection увидела
		// content before terminal signal).
		if hasFinish {
			return emit(Event{
				Type:     EventMessageStop,
				RawBytes: f.Raw,
				Meta:     metaWithModel(gf.ModelVersion),
			})
		}
		// Default: delta text — склеиваем все parts всех candidates.
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

// EmitSanitized replaces Gemini candidates[].content.parts[].text while
// preserving the data-only SSE frame shape. Non-text / empty delta events
// remain identity.
func (e GeminiEmitter) EmitSanitized(ctx context.Context, w io.Writer, ev Event, sanitizedText string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ev.Type != EventDeltaText || len(ev.RawBytes) == 0 || ev.Text == "" {
		return e.Emit(ctx, w, ev)
	}
	frame, err := parseSingleSSEFrame(ev.RawBytes, "gemini sanitize")
	if err != nil {
		return err
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(frame.Data, &outer); err != nil {
		return fmt.Errorf("streaming: gemini sanitize: unmarshal outer: %w", err)
	}
	candidatesRaw, ok := outer["candidates"]
	if !ok || len(candidatesRaw) == 0 {
		return fmt.Errorf("streaming: gemini sanitize: missing candidates")
	}
	var candidates []json.RawMessage
	if err := json.Unmarshal(candidatesRaw, &candidates); err != nil {
		return fmt.Errorf("streaming: gemini sanitize: unmarshal candidates: %w", err)
	}
	replaced := false
	sanitizedJSON, err := json.Marshal(sanitizedText)
	if err != nil {
		return fmt.Errorf("streaming: gemini sanitize: marshal text: %w", err)
	}
	emptyJSON := json.RawMessage(`""`)
	for i, candidateRaw := range candidates {
		var candidate map[string]json.RawMessage
		if err := json.Unmarshal(candidateRaw, &candidate); err != nil {
			return fmt.Errorf("streaming: gemini sanitize: unmarshal candidate %d: %w", i, err)
		}
		contentRaw, ok := candidate["content"]
		if !ok || len(contentRaw) == 0 {
			continue
		}
		var content map[string]json.RawMessage
		if err := json.Unmarshal(contentRaw, &content); err != nil {
			return fmt.Errorf("streaming: gemini sanitize: unmarshal content %d: %w", i, err)
		}
		partsRaw, ok := content["parts"]
		if !ok || len(partsRaw) == 0 {
			continue
		}
		var parts []json.RawMessage
		if err := json.Unmarshal(partsRaw, &parts); err != nil {
			return fmt.Errorf("streaming: gemini sanitize: unmarshal parts %d: %w", i, err)
		}
		for j, partRaw := range parts {
			var part map[string]json.RawMessage
			if err := json.Unmarshal(partRaw, &part); err != nil {
				return fmt.Errorf("streaming: gemini sanitize: unmarshal part %d.%d: %w", i, j, err)
			}
			if _, hasText := part["text"]; !hasText {
				continue
			}
			if !replaced {
				part["text"] = sanitizedJSON
				replaced = true
			} else {
				part["text"] = emptyJSON
			}
			newPart, err := json.Marshal(part)
			if err != nil {
				return fmt.Errorf("streaming: gemini sanitize: marshal part %d.%d: %w", i, j, err)
			}
			parts[j] = newPart
		}
		newParts, err := json.Marshal(parts)
		if err != nil {
			return fmt.Errorf("streaming: gemini sanitize: marshal parts %d: %w", i, err)
		}
		content["parts"] = newParts
		newContent, err := json.Marshal(content)
		if err != nil {
			return fmt.Errorf("streaming: gemini sanitize: marshal content %d: %w", i, err)
		}
		candidate["content"] = newContent
		newCandidate, err := json.Marshal(candidate)
		if err != nil {
			return fmt.Errorf("streaming: gemini sanitize: marshal candidate %d: %w", i, err)
		}
		candidates[i] = newCandidate
	}
	if !replaced {
		return fmt.Errorf("streaming: gemini sanitize: missing text part")
	}
	newCandidates, err := json.Marshal(candidates)
	if err != nil {
		return fmt.Errorf("streaming: gemini sanitize: marshal candidates: %w", err)
	}
	outer["candidates"] = newCandidates
	newPayload, err := json.Marshal(outer)
	if err != nil {
		return fmt.Errorf("streaming: gemini sanitize: marshal outer: %w", err)
	}
	return writeSSEJSON(ctx, w, "", newPayload)
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

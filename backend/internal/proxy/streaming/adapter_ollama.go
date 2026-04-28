package streaming

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// OllamaDecoder парсит Ollama NDJSON streaming: по одному JSON-объекту
// на строку, terminator — `\n`.
//
// Map (Ollama /api/chat format):
//
//	message.content (done=false)  → EventDeltaText
//	done=true + eval_count        → EventUsageUpdate + EventMessageStop
//	error поле                    → EventProviderError
//	malformed line                → EventUnknownChunk
//
// Ollama шлёт финальный frame c `done:true` и usage (eval_count,
// prompt_eval_count). В терминах normalized events это и
// usage_update, и message_stop — F7.1 эмитит их как TWO events из
// одного frame'а: сначала usage_update (RawBytes = pointer to line),
// затем message_stop (RawBytes = empty, чтобы не дублировать bytes
// в emitter'е). **Это нарушит identity** в этой конкретной ситуации;
// альтернатива — эмитить одно event'о с обоими ролями, но это
// усложнит F7.2 dispatch.
//
// Решение F7.1: эмитим ОДНО event типа EventUsageUpdate с полным
// RawBytes; message_stop интенция выражается через Meta["done"]="true".
// F7.2 декодирует done=true напрямую из Meta. Таким образом identity
// сохраняется: один line → один Event с его RawBytes.
type OllamaDecoder struct{}

type ollamaFrame struct {
	Model   string `json:"model"`
	Message *struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"message,omitempty"`
	Response string `json:"response"` // /api/generate shape
	Done     bool   `json:"done"`
	// Usage fields (присутствуют в финальном frame):
	PromptEvalCount int    `json:"prompt_eval_count"`
	EvalCount       int    `json:"eval_count"`
	Error           string `json:"error"`
}

func (OllamaDecoder) Decode(ctx context.Context, r io.Reader, emit func(Event) error) error {
	br := bufio.NewReaderSize(r, 1024*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			// Skip empty line (терминатор без содержимого).
			trimmed := bytes.TrimRight(line, "\r\n")
			if len(trimmed) == 0 {
				if err != nil && err != io.EOF {
					return err
				}
				if err == io.EOF {
					return nil
				}
				continue
			}
			var of ollamaFrame
			if jerr := json.Unmarshal(trimmed, &of); jerr != nil {
				if eerr := emit(Event{
					Type:     EventUnknownChunk,
					RawBytes: append([]byte(nil), line...),
				}); eerr != nil {
					return eerr
				}
			} else {
				ev := normalizeOllama(of, line)
				if eerr := emit(ev); eerr != nil {
					return eerr
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// normalizeOllama конвертирует parsed frame в Event. RawBytes всегда
// = оригинальный line (с terminator'ом \n если был).
func normalizeOllama(of ollamaFrame, raw []byte) Event {
	rb := append([]byte(nil), raw...)
	meta := metaWithModel(of.Model)
	// Error path.
	if of.Error != "" {
		return Event{
			Type:     EventProviderError,
			Text:     of.Error,
			RawBytes: rb,
			ProviderErr: &ProviderError{
				Code:    "ollama_error",
				Message: of.Error,
				Raw:     append([]byte(nil), rb...),
			},
			Meta: meta,
		}
	}
	// Final frame: done=true с usage. Эмитим как usage_update;
	// терминация stream'а выражается через Meta["done"]=true и через
	// natural end-of-stream (io.EOF на следующей итерации).
	if of.Done {
		if meta == nil {
			meta = map[string]string{}
		}
		meta["done"] = "true"
		return Event{
			Type:     EventUsageUpdate,
			RawBytes: rb,
			Usage: &Usage{
				PromptTokens:     of.PromptEvalCount,
				CompletionTokens: of.EvalCount,
				TotalTokens:      of.PromptEvalCount + of.EvalCount,
				Model:            of.Model,
			},
			Meta: meta,
		}
	}
	// Regular delta. Поддерживаем обе формы: /api/chat (message.content)
	// и /api/generate (response).
	var text string
	if of.Message != nil {
		text = of.Message.Content
	} else {
		text = of.Response
	}
	return Event{
		Type:     EventDeltaText,
		Text:     text,
		RawBytes: rb,
		Meta:     meta,
	}
}

// OllamaEmitter — identity NDJSON emitter.
type OllamaEmitter struct{}

// EmitSanitized replaces /api/chat message.content or /api/generate response
// while preserving the NDJSON line shape. Non-text / empty delta events remain
// identity.
func (e OllamaEmitter) EmitSanitized(ctx context.Context, w io.Writer, ev Event, sanitizedText string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ev.Type != EventDeltaText || len(ev.RawBytes) == 0 || ev.Text == "" {
		return e.Emit(ctx, w, ev)
	}
	payload := bytes.TrimSpace(ev.RawBytes)
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(payload, &outer); err != nil {
		return fmt.Errorf("streaming: ollama sanitize: unmarshal outer: %w", err)
	}
	sanitizedJSON, err := json.Marshal(sanitizedText)
	if err != nil {
		return fmt.Errorf("streaming: ollama sanitize: marshal text: %w", err)
	}
	if messageRaw, ok := outer["message"]; ok && len(messageRaw) > 0 {
		var message map[string]json.RawMessage
		if err := json.Unmarshal(messageRaw, &message); err != nil {
			return fmt.Errorf("streaming: ollama sanitize: unmarshal message: %w", err)
		}
		if _, ok := message["content"]; !ok {
			return fmt.Errorf("streaming: ollama sanitize: missing message.content")
		}
		message["content"] = sanitizedJSON
		newMessage, err := json.Marshal(message)
		if err != nil {
			return fmt.Errorf("streaming: ollama sanitize: marshal message: %w", err)
		}
		outer["message"] = newMessage
	} else if _, ok := outer["response"]; ok {
		outer["response"] = sanitizedJSON
	} else {
		return fmt.Errorf("streaming: ollama sanitize: missing message.content or response")
	}
	newPayload, err := json.Marshal(outer)
	if err != nil {
		return fmt.Errorf("streaming: ollama sanitize: marshal outer: %w", err)
	}
	if _, err := w.Write(append(newPayload, '\n')); err != nil {
		return err
	}
	flushIfPossible(w)
	return nil
}

func (OllamaEmitter) Emit(ctx context.Context, w io.Writer, ev Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(ev.RawBytes) == 0 {
		return fmt.Errorf("streaming: ollama emit without RawBytes is not supported in F7.1")
	}
	if _, err := w.Write(ev.RawBytes); err != nil {
		return err
	}
	flushIfPossible(w)
	return nil
}

// EmitError — NDJSON line с error payload. Формат commensurate с
// тем, что Ollama возвращает в ошибочных ответах: {"error":"..."}.
// code передаётся в отдельное поле "code" (не-стандартное, но
// клиентам помогает отличить наш streaming-level error).
func (OllamaEmitter) EmitError(ctx context.Context, w io.Writer, code, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"error": message,
		"code":  code,
		"done":  true,
	})
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.Write(payload)
	buf.WriteByte('\n')
	if _, err := w.Write(buf.Bytes()); err != nil {
		return err
	}
	flushIfPossible(w)
	return nil
}

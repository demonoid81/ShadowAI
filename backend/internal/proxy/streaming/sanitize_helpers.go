package streaming

import (
	"bytes"
	"context"
	"fmt"
	"io"
)

func parseSingleSSEFrame(raw []byte, label string) (sseFrame, error) {
	var frames []sseFrame
	if err := readSSEFrames(bytes.NewReader(raw), func(f sseFrame) error {
		frames = append(frames, f)
		return nil
	}); err != nil {
		return sseFrame{}, fmt.Errorf("streaming: %s: parse SSE frame: %w", label, err)
	}
	if len(frames) != 1 {
		return sseFrame{}, fmt.Errorf("streaming: %s: expected 1 SSE frame, got %d", label, len(frames))
	}
	if len(frames[0].Data) == 0 {
		return sseFrame{}, fmt.Errorf("streaming: %s: empty SSE data", label)
	}
	return frames[0], nil
}

func writeSSEJSON(ctx context.Context, w io.Writer, eventName string, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var buf bytes.Buffer
	if eventName != "" {
		buf.WriteString("event: ")
		buf.WriteString(eventName)
		buf.WriteByte('\n')
	}
	buf.WriteString("data: ")
	buf.Write(payload)
	buf.WriteString("\n\n")
	if _, err := w.Write(buf.Bytes()); err != nil {
		return err
	}
	flushIfPossible(w)
	return nil
}

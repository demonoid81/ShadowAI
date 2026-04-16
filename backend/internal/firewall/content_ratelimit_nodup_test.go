package firewall

import (
	"context"
	"testing"
	"time"
)

// TestContentRateLimiter_NoDoubleCount — регрессия на баг double-count'а,
// когда len(Text) и len(Messages[].Content) суммировались для одного и того
// же контента (handler заполняет оба поля одними данными).
func TestContentRateLimiter_NoDoubleCount(t *testing.T) {
	rl := NewContentRateLimiter(ContentRateLimitConfig{
		Enabled:           true,
		MaxCharsPerMinute: 100,
		Window:            time.Minute,
	})

	// Messages содержат 60 символов суммарно
	msg := "a" + string(make([]byte, 59))
	for i := 1; i < 60; i++ {
		msg = msg[:i] + "a" + msg[i+1:]
	}
	// build 60-char string
	b := make([]byte, 60)
	for i := range b {
		b[i] = 'a'
	}
	content := string(b)

	payload := &Payload{
		UserID:   "u1",
		Text:     content, // handler дублирует: Text = concat(Messages)
		Messages: []Message{{Role: "user", Content: content}},
	}

	// Первый вызов: 60 символов (Messages), НЕ 120 (Text + Messages). Должен пройти.
	d1, err := rl.InspectRequest(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if d1.Action != ActionAllow {
		t.Fatalf("первый запрос с 60 chars должен быть allowed (не double-count'иться до 120), got %s: %s",
			d1.Action, d1.Reason)
	}

	// Второй вызов: ещё 60 символов → всего 120 > 100 → block.
	payload2 := &Payload{
		UserID:   "u1",
		Text:     content,
		Messages: []Message{{Role: "user", Content: content}},
	}
	d2, err := rl.InspectRequest(context.Background(), payload2)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Action != ActionBlock {
		t.Errorf("второй запрос должен быть блокирован (суммарно 120 > 100), got %s", d2.Action)
	}
}

// TestContentRateLimiter_TextOnlyFallback — если Messages пуст, использовать Text.
func TestContentRateLimiter_TextOnlyFallback(t *testing.T) {
	rl := NewContentRateLimiter(ContentRateLimitConfig{
		Enabled:           true,
		MaxCharsPerMinute: 50,
	})

	payload := &Payload{
		UserID: "u1",
		Text:   "hello world", // 11 chars
	}
	d, err := rl.InspectRequest(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionAllow {
		t.Errorf("text-only 11 chars должен пройти, got %s", d.Action)
	}
}

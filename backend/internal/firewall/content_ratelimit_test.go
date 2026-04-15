package firewall

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestContentRateLimitAllowWithinLimits(t *testing.T) {
	rl := NewContentRateLimiter(ContentRateLimitConfig{
		Enabled:           true,
		MaxCharsPerMinute: 1000,
		MaxFlagsPerMinute: 5,
		Window:            time.Minute,
	})

	d, err := rl.InspectRequest(context.Background(), &Payload{
		Text:   "hello",
		UserID: "user1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionAllow {
		t.Fatalf("expected allow, got %s", d.Action)
	}
}

func TestContentRateLimitBlockExceedChars(t *testing.T) {
	rl := NewContentRateLimiter(ContentRateLimitConfig{
		Enabled:           true,
		MaxCharsPerMinute: 10,
		MaxFlagsPerMinute: 5,
		Window:            time.Minute,
	})

	d, err := rl.InspectRequest(context.Background(), &Payload{
		Text:   "this is more than ten characters",
		UserID: "user1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionBlock {
		t.Fatalf("expected block, got %s", d.Action)
	}
}

func TestContentRateLimitAccumulatingRequests(t *testing.T) {
	rl := NewContentRateLimiter(ContentRateLimitConfig{
		Enabled:           true,
		MaxCharsPerMinute: 20,
		MaxFlagsPerMinute: 5,
		Window:            time.Minute,
	})

	// Первый запрос: 10 символов — должен пройти
	d, err := rl.InspectRequest(context.Background(), &Payload{
		Text:   "1234567890",
		UserID: "user1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionAllow {
		t.Fatalf("first request: expected allow, got %s", d.Action)
	}

	// Второй запрос: 10 символов — должен пройти (итого 20)
	d, err = rl.InspectRequest(context.Background(), &Payload{
		Text:   "abcdefghij",
		UserID: "user1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionAllow {
		t.Fatalf("second request: expected allow, got %s", d.Action)
	}

	// Третий запрос: 1 символ — должен заблокировать (21 > 20)
	d, err = rl.InspectRequest(context.Background(), &Payload{
		Text:   "x",
		UserID: "user1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionBlock {
		t.Fatalf("third request: expected block, got %s", d.Action)
	}
}

func TestContentRateLimitWindowExpiry(t *testing.T) {
	rl := NewContentRateLimiter(ContentRateLimitConfig{
		Enabled:           true,
		MaxCharsPerMinute: 10,
		MaxFlagsPerMinute: 5,
		Window:            50 * time.Millisecond,
	})

	// Заполняем лимит
	d, err := rl.InspectRequest(context.Background(), &Payload{
		Text:   "1234567890",
		UserID: "user1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionAllow {
		t.Fatalf("expected allow, got %s", d.Action)
	}

	// Следующий запрос блокируется
	d, err = rl.InspectRequest(context.Background(), &Payload{
		Text:   "x",
		UserID: "user1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionBlock {
		t.Fatalf("expected block before expiry, got %s", d.Action)
	}

	// Ждём истечения окна
	time.Sleep(60 * time.Millisecond)

	// После истечения — снова разрешено
	d, err = rl.InspectRequest(context.Background(), &Payload{
		Text:   "x",
		UserID: "user1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionAllow {
		t.Fatalf("expected allow after expiry, got %s", d.Action)
	}
}

func TestContentRateLimitEmptyUserID(t *testing.T) {
	rl := NewContentRateLimiter(ContentRateLimitConfig{
		Enabled:           true,
		MaxCharsPerMinute: 1,
		MaxFlagsPerMinute: 1,
		Window:            time.Minute,
	})

	d, err := rl.InspectRequest(context.Background(), &Payload{
		Text:   "this exceeds the limit but has no user ID",
		UserID: "",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionAllow {
		t.Fatalf("expected allow for empty UserID, got %s", d.Action)
	}
}

func TestContentRateLimitDisabled(t *testing.T) {
	rl := NewContentRateLimiter(ContentRateLimitConfig{
		Enabled:           false,
		MaxCharsPerMinute: 1,
		MaxFlagsPerMinute: 1,
		Window:            time.Minute,
	})

	d, err := rl.InspectRequest(context.Background(), &Payload{
		Text:   "this exceeds the limit but limiter is disabled",
		UserID: "user1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionAllow {
		t.Fatalf("expected allow when disabled, got %s", d.Action)
	}
}

func TestContentRateLimitResponseAlwaysAllows(t *testing.T) {
	rl := NewContentRateLimiter(ContentRateLimitConfig{
		Enabled:           true,
		MaxCharsPerMinute: 1,
		MaxFlagsPerMinute: 1,
		Window:            time.Minute,
	})

	d, err := rl.InspectResponse(context.Background(), &Payload{
		Text:   "lots of text that would exceed any limit",
		UserID: "user1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionAllow {
		t.Fatalf("expected allow for response, got %s", d.Action)
	}
}

func TestContentRateLimitRecordFlagBlocksAfterThreshold(t *testing.T) {
	rl := NewContentRateLimiter(ContentRateLimitConfig{
		Enabled:           true,
		MaxCharsPerMinute: 100000,
		MaxFlagsPerMinute: 3,
		Window:            time.Minute,
	})

	// Записываем 3 флага
	rl.RecordFlag("user1")
	rl.RecordFlag("user1")
	rl.RecordFlag("user1")

	// Запрос должен быть заблокирован из-за флагов
	d, err := rl.InspectRequest(context.Background(), &Payload{
		Text:   "hi",
		UserID: "user1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionBlock {
		t.Fatalf("expected block after flag threshold, got %s", d.Action)
	}
	if d.Severity != SeverityHigh {
		t.Fatalf("expected high severity for flag block, got %s", d.Severity)
	}
}

func TestContentRateLimitConcurrentAccess(t *testing.T) {
	rl := NewContentRateLimiter(ContentRateLimitConfig{
		Enabled:           true,
		MaxCharsPerMinute: 1000000,
		MaxFlagsPerMinute: 100000,
		Window:            time.Minute,
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := rl.InspectRequest(context.Background(), &Payload{
				Text:   "concurrent test",
				UserID: "user1",
			})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}

	// Параллельные RecordFlag
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rl.RecordFlag("user1")
		}()
	}

	wg.Wait()
}

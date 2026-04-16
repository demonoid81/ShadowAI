package firewall

import (
	"context"
	"testing"
	"time"
)

// TestMultiTurn_DeduplicatesResentHistory — регрессия на баг, когда chat-клиент
// resend'ил всю историю на каждом turn, и сессия накапливала дубликаты.
// Теперь одинаковый контент не добавляется повторно.
func TestMultiTurn_DeduplicatesResentHistory(t *testing.T) {
	mt := NewMultiTurnInspector(MultiTurnConfig{
		Enabled:            true,
		WindowSize:         10,
		HeuristicThreshold: 0.9, // высокий, чтобы не блокировать benign-контент
		SessionTTL:         time.Minute,
	})

	userID := "user-1"

	// Turn 1: клиент отправляет 2 сообщения
	_, err := mt.InspectRequest(context.Background(), &Payload{
		UserID: userID,
		Messages: []Message{
			{Role: "user", Content: "Hello, how are you?"},
			{Role: "assistant", Content: "I'm well, thanks!"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Turn 2: клиент отправляет ВСЮ историю + новое сообщение
	_, err = mt.InspectRequest(context.Background(), &Payload{
		UserID: userID,
		Messages: []Message{
			{Role: "user", Content: "Hello, how are you?"},      // дубликат
			{Role: "assistant", Content: "I'm well, thanks!"},   // дубликат
			{Role: "user", Content: "What's the weather today?"}, // новое
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Проверяем состояние сессии — должно быть ровно 3 уникальных сообщения,
	// а не 5 (2 + 3 с дубликатами).
	mt.mu.RLock()
	session, ok := mt.sessions[userID]
	mt.mu.RUnlock()
	if !ok {
		t.Fatal("session not found")
	}

	session.mu.Lock()
	count := len(session.messages)
	session.mu.Unlock()

	if count != 3 {
		t.Errorf("ожидалось 3 уникальных сообщения в сессии, получено %d (дубликаты не дедуплицировались)", count)
	}
}

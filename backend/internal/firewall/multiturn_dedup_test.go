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

// TestMultiTurn_ConversationIDIsolation — разные conversation_id одного
// пользователя должны иметь раздельные сессии, иначе атака в одном чате
// повлияет на нейтральный параллельный чат.
func TestMultiTurn_ConversationIDIsolation(t *testing.T) {
	mt := NewMultiTurnInspector(MultiTurnConfig{
		Enabled:            true,
		WindowSize:         10,
		HeuristicThreshold: 0.9,
		SessionTTL:         time.Minute,
	})

	userID := "user-1"

	// Conversation A: клиент шлёт "hello"
	_, err := mt.InspectRequest(context.Background(), &Payload{
		UserID:   userID,
		Messages: []Message{{Role: "user", Content: "hello from conv A"}},
		Meta:     map[string]string{"conversation_id": "conv-A"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Conversation B: тот же user, другой чат
	_, err = mt.InspectRequest(context.Background(), &Payload{
		UserID:   userID,
		Messages: []Message{{Role: "user", Content: "hello from conv B"}},
		Meta:     map[string]string{"conversation_id": "conv-B"},
	})
	if err != nil {
		t.Fatal(err)
	}

	mt.mu.RLock()
	sessionA, okA := mt.sessions[userID+":conv-A"]
	sessionB, okB := mt.sessions[userID+":conv-B"]
	mt.mu.RUnlock()

	if !okA {
		t.Fatal("сессия conv-A не создана")
	}
	if !okB {
		t.Fatal("сессия conv-B не создана")
	}

	sessionA.mu.Lock()
	countA := len(sessionA.messages)
	contentA := ""
	if countA > 0 {
		contentA = sessionA.messages[0].content
	}
	sessionA.mu.Unlock()

	sessionB.mu.Lock()
	countB := len(sessionB.messages)
	contentB := ""
	if countB > 0 {
		contentB = sessionB.messages[0].content
	}
	sessionB.mu.Unlock()

	if countA != 1 || contentA != "hello from conv A" {
		t.Errorf("conv-A сессия должна содержать 1 сообщение 'hello from conv A', got %d: %q", countA, contentA)
	}
	if countB != 1 || contentB != "hello from conv B" {
		t.Errorf("conv-B сессия должна содержать 1 сообщение 'hello from conv B', got %d: %q", countB, contentB)
	}
}

// TestMultiTurn_LegacyWithoutConversationID — без conversation_id
// сохраняется старое поведение (fallback на userID-only session).
func TestMultiTurn_LegacyWithoutConversationID(t *testing.T) {
	mt := NewMultiTurnInspector(MultiTurnConfig{
		Enabled:            true,
		WindowSize:         10,
		HeuristicThreshold: 0.9,
		SessionTTL:         time.Minute,
	})

	_, err := mt.InspectRequest(context.Background(), &Payload{
		UserID:   "user-1",
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	mt.mu.RLock()
	_, ok := mt.sessions["user-1"]
	mt.mu.RUnlock()
	if !ok {
		t.Errorf("без conversation_id ожидается fallback на userID-only session key, но сессия 'user-1' не найдена")
	}
}

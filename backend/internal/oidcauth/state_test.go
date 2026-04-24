//go:build enterprise

package oidcauth

import (
	"testing"
	"time"
)

// TestStateStore_NewAndConsume — happy path: new state, consume with correct nonce.
func TestStateStore_NewAndConsume(t *testing.T) {
	s := &StateStore{store: make(map[string]stateEntry)}
	state, nonce, err := s.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if state == "" || nonce == "" {
		t.Error("state and nonce must be non-empty")
	}

	got, err := s.Consume(state)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got != nonce {
		t.Errorf("Consume nonce = %q, want %q", got, nonce)
	}
}

// TestStateStore_ConsumeRemovesEntry — entry is removed after consume (no replay).
func TestStateStore_ConsumeRemovesEntry(t *testing.T) {
	s := &StateStore{store: make(map[string]stateEntry)}
	state, _, _ := s.New()
	s.Consume(state) // first consume — OK
	_, err := s.Consume(state) // second consume — must fail
	if err == nil {
		t.Error("second Consume must return error (entry removed after first)")
	}
}

// TestStateStore_UnknownState_Rejects — unknown state → error.
func TestStateStore_UnknownState_Rejects(t *testing.T) {
	s := &StateStore{store: make(map[string]stateEntry)}
	_, err := s.Consume("does-not-exist")
	if err == nil {
		t.Error("unknown state must be rejected")
	}
}

// TestStateStore_Expired_Rejects — expired entry → error.
func TestStateStore_Expired_Rejects(t *testing.T) {
	s := &StateStore{store: make(map[string]stateEntry)}
	state, _, _ := s.New()
	// Manually backdate the entry.
	s.mu.Lock()
	e := s.store[state]
	e.expiresAt = time.Now().Add(-time.Hour)
	s.store[state] = e
	s.mu.Unlock()

	_, err := s.Consume(state)
	if err == nil {
		t.Error("expired state must be rejected")
	}
}

// TestStateStore_EachStateUnique — two New() calls return distinct states.
func TestStateStore_EachStateUnique(t *testing.T) {
	s := &StateStore{store: make(map[string]stateEntry)}
	s1, n1, _ := s.New()
	s2, n2, _ := s.New()
	if s1 == s2 {
		t.Error("state tokens must be unique")
	}
	if n1 == n2 {
		t.Error("nonce values must be unique")
	}
}

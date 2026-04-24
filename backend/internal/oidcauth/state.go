//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package oidcauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	stateCookieName = "oidc_state"
	nonceCookieName = "oidc_nonce"
	stateExpiry     = 10 * time.Minute
	cookiePath      = "/api/auth/oidc"
)

// StateStore holds pending state→nonce pairs for CSRF protection.
// In-memory; safe for single-instance deploys. For multi-instance,
// replace with Redis or signed cookie (state+HMAC).
type StateStore struct {
	mu    sync.Mutex
	store map[string]stateEntry
}

type stateEntry struct {
	nonce     string
	expiresAt time.Time
}

// NewStateStore creates a StateStore.
func NewStateStore() *StateStore {
	s := &StateStore{store: make(map[string]stateEntry)}
	go s.cleanup()
	return s
}

// New generates a random state and nonce, stores the mapping, and returns both.
func (s *StateStore) New() (state, nonce string, err error) {
	state, err = randomToken()
	if err != nil {
		return "", "", fmt.Errorf("state gen: %w", err)
	}
	nonce, err = randomToken()
	if err != nil {
		return "", "", fmt.Errorf("nonce gen: %w", err)
	}
	s.mu.Lock()
	s.store[state] = stateEntry{nonce: nonce, expiresAt: time.Now().Add(stateExpiry)}
	s.mu.Unlock()
	return state, nonce, nil
}

// Consume verifies state and returns the associated nonce. Removes the entry.
// Returns an error if the state is unknown or expired.
func (s *StateStore) Consume(state string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.store[state]
	if !ok {
		return "", fmt.Errorf("unknown or expired state")
	}
	delete(s.store, state)
	if time.Now().After(e.expiresAt) {
		return "", fmt.Errorf("state expired")
	}
	return e.nonce, nil
}

// SetCookies writes short-lived SameSite=Lax cookies for state and nonce.
func SetCookies(w http.ResponseWriter, state, nonce string, secure bool) {
	maxAge := int(stateExpiry.Seconds())
	for _, kv := range []struct{ name, val string }{
		{stateCookieName, state},
		{nonceCookieName, nonce},
	} {
		http.SetCookie(w, &http.Cookie{
			Name:     kv.name,
			Value:    kv.val,
			Path:     cookiePath,
			MaxAge:   maxAge,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

// ClearCookies deletes the state/nonce cookies after the callback.
func ClearCookies(w http.ResponseWriter) {
	for _, name := range []string{stateCookieName, nonceCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:   name,
			Path:   cookiePath,
			MaxAge: -1,
		})
	}
}

func randomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *StateStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for k, e := range s.store {
			if now.After(e.expiresAt) {
				delete(s.store, k)
			}
		}
		s.mu.Unlock()
	}
}

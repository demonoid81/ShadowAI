package firewall

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ContentRateLimitConfig задаёт параметры ограничения скорости контента.
type ContentRateLimitConfig struct {
	Enabled           bool
	MaxCharsPerMinute int           // максимум символов на пользователя за окно (по умолчанию 50000)
	MaxFlagsPerMinute int           // максимум флагов до блокировки (по умолчанию 5)
	Window            time.Duration // скользящее окно (по умолчанию 1 минута)
}

func (c ContentRateLimitConfig) withDefaults() ContentRateLimitConfig {
	if c.MaxCharsPerMinute == 0 {
		c.MaxCharsPerMinute = 50000
	}
	if c.MaxFlagsPerMinute == 0 {
		c.MaxFlagsPerMinute = 5
	}
	if c.Window == 0 {
		c.Window = time.Minute
	}
	return c
}

type contentWindow struct {
	chars     int
	flags     int
	expiresAt time.Time
}

// ContentRateLimiter отслеживает объём контента и количество флагов на пользователя.
type ContentRateLimiter struct {
	config  ContentRateLimitConfig
	mu      sync.Mutex
	windows map[string]*contentWindow
}

// NewContentRateLimiter создаёт новый ContentRateLimiter с заданной конфигурацией.
func NewContentRateLimiter(cfg ContentRateLimitConfig) *ContentRateLimiter {
	cfg = cfg.withDefaults()
	return &ContentRateLimiter{
		config:  cfg,
		windows: make(map[string]*contentWindow),
	}
}

func (r *ContentRateLimiter) Name() string {
	return "content_ratelimit"
}

// getOrResetWindow возвращает текущее окно пользователя, сбрасывая при истечении.
// Вызывать под блокировкой mu.
func (r *ContentRateLimiter) getOrResetWindow(userID string) *contentWindow {
	w, ok := r.windows[userID]
	if !ok || time.Now().After(w.expiresAt) {
		w = &contentWindow{
			expiresAt: time.Now().Add(r.config.Window),
		}
		r.windows[userID] = w
	}
	return w
}

func (r *ContentRateLimiter) InspectRequest(_ context.Context, p *Payload) (*Decision, error) {
	if !r.config.Enabled {
		return &Decision{Action: ActionAllow, InspectorName: r.Name()}, nil
	}
	if p.UserID == "" {
		return &Decision{Action: ActionAllow, InspectorName: r.Name()}, nil
	}

	textLen := len(p.Text)
	for _, m := range p.Messages {
		textLen += len(m.Content)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	w := r.getOrResetWindow(p.UserID)

	// Проверка флагов
	if w.flags >= r.config.MaxFlagsPerMinute {
		return &Decision{
			Action:        ActionBlock,
			Reason:        fmt.Sprintf("user exceeded flag limit: %d flags in window", w.flags),
			Severity:      SeverityHigh,
			InspectorName: r.Name(),
			Findings: []Finding{
				{
					Type:     "content_ratelimit_flags",
					Severity: SeverityHigh,
					Match:    fmt.Sprintf("flags=%d, limit=%d", w.flags, r.config.MaxFlagsPerMinute),
				},
			},
		}, nil
	}

	// Проверка символов
	if w.chars+textLen > r.config.MaxCharsPerMinute {
		return &Decision{
			Action:        ActionBlock,
			Reason:        fmt.Sprintf("user exceeded character limit: %d + %d > %d", w.chars, textLen, r.config.MaxCharsPerMinute),
			Severity:      SeverityMedium,
			InspectorName: r.Name(),
			Findings: []Finding{
				{
					Type:     "content_ratelimit_chars",
					Severity: SeverityMedium,
					Match:    fmt.Sprintf("chars=%d, incoming=%d, limit=%d", w.chars, textLen, r.config.MaxCharsPerMinute),
				},
			},
		}, nil
	}

	w.chars += textLen

	return &Decision{Action: ActionAllow, InspectorName: r.Name()}, nil
}

func (r *ContentRateLimiter) InspectResponse(_ context.Context, _ *Payload) (*Decision, error) {
	return &Decision{Action: ActionAllow, InspectorName: r.Name()}, nil
}

// RecordFlag увеличивает счётчик флагов для пользователя.
func (r *ContentRateLimiter) RecordFlag(userID string) {
	if userID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	w := r.getOrResetWindow(userID)
	w.flags++
}

// Cleanup удаляет истёкшие окна.
func (r *ContentRateLimiter) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for uid, w := range r.windows {
		if now.After(w.expiresAt) {
			delete(r.windows, uid)
		}
	}
}

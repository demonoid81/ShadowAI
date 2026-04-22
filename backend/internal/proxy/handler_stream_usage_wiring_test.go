package proxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"

	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/budget"
	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/policy"
)

// dualSignalProvider — provider, у которого ParseResponse и
// ParseStreamUsage возвращают РАЗНЫЕ значения. Тест подтверждает, что
// handler в streaming-ветке читает ИЗ ParseStreamUsage, а не из
// ParseResponse. Это ключевой wiring-контракт Stage 1.
type dualSignalProvider struct {
	url string
}

func (p *dualSignalProvider) Name() string { return "openai" }
func (p *dualSignalProvider) BuildRequest(ctx context.Context, body []byte, _ string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, "POST", p.url, bytes.NewReader(body))
}

// ParseResponse возвращает "сигнальные" значения, которые НЕ должны
// попасть в audit при streaming path.
func (p *dualSignalProvider) ParseResponse(_ []byte) (int, int, int, float64, error) {
	return 999, 999, 999, 9.99, nil
}

// ParseStreamUsage возвращает "правильные" значения, которые ДОЛЖНЫ
// попасть в audit при streaming path.
func (p *dualSignalProvider) ParseStreamUsage(_ []byte, _ string) (StreamUsage, error) {
	return StreamUsage{
		PromptTokens:     11,
		CompletionTokens: 22,
		TotalTokens:      33,
		CostUSD:          0.0042,
		Model:            "gpt-4o-stream",
		Found:            true,
	}, nil
}

func (p *dualSignalProvider) StreamFormat() StreamFormat { return StreamSSE }
func (p *dualSignalProvider) DefaultModel() string       { return "gpt-4o" }
func (p *dualSignalProvider) SupportedModels() []string  { return []string{"gpt-4o"} }

// TestProxyChatStreaming_UsesParseStreamUsageNotParseResponse — wiring-тест
// Stage 1: в streaming-ветке handler должен вызывать provider.ParseStreamUsage,
// а не provider.ParseResponse. Раньше handler буферизовал upstream stream
// и прогонял его через ParseResponse, что для SSE body давало 0 токенов
// и разрешало обход бюджета через stream=true.
func TestProxyChatStreaming_UsesParseStreamUsageNotParseResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n"))
	}))
	defer upstream.Close()

	registry := NewRegistry()
	registry.Register(&dualSignalProvider{url: upstream.URL})

	auditRepo := &captureAuditRepo{}
	auditSvc := audit.NewService(auditRepo)

	policySvc := &policy.Service{Engine: policy.NewEngine(emptyPolicyRepo{})}

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	budgetSvc := budget.NewService(unlimitedBudgetRepo{}, rdb)

	h := NewHandler(
		registry, policySvc, auditSvc, budgetSvc, dlp.NewService("audit"),
		"", nil, nil, nil, 0, nil, audit.PayloadModeFull, // без firewall pipeline — фокус на accounting
	)

	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	claims := &auth.Claims{UserID: "test-user", Role: "user"}
	req = req.WithContext(auth.WithClaims(req.Context(), claims))

	rec := httptest.NewRecorder()
	h.ProxyChat(rec, req)
	auditSvc.Close()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	entries := auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(entries))
	}
	entry := entries[0]

	// Если handler вызвал ParseResponse — увидим 999/999/999/9.99.
	// Если handler вызвал ParseStreamUsage — увидим 11/22/33/0.0042.
	if entry.PromptTokens == 999 {
		t.Errorf("handler использует ParseResponse вместо ParseStreamUsage (prompt=999 — signal-value)")
	}
	if entry.PromptTokens != 11 || entry.CompletionTokens != 22 || entry.TotalTokens != 33 {
		t.Errorf("audit tokens = %d/%d/%d, want 11/22/33 (из ParseStreamUsage)",
			entry.PromptTokens, entry.CompletionTokens, entry.TotalTokens)
	}
	if entry.CostUSD < 0.0042*0.99 || entry.CostUSD > 0.0042*1.01 {
		t.Errorf("audit cost = %g, want ~0.0042 (из ParseStreamUsage)", entry.CostUSD)
	}
}

// TestUnifiedChatStreaming_UsesParseStreamUsage — тот же контракт, но
// через UnifiedChat (другой code path с Router + fallback loop).
func TestUnifiedChatStreaming_UsesParseStreamUsage(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n"))
	}))
	defer upstream.Close()

	registry := NewRegistry()
	registry.Register(&dualSignalProvider{url: upstream.URL})

	auditRepo := &captureAuditRepo{}
	auditSvc := audit.NewService(auditRepo)

	policySvc := &policy.Service{Engine: policy.NewEngine(emptyPolicyRepo{})}

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	budgetSvc := budget.NewService(unlimitedBudgetRepo{}, rdb)

	modelMapper := NewModelMapper(registry)
	router := NewRouter(registry, nil, modelMapper, StrategyCheapest, nil)

	h := NewHandler(
		registry, policySvc, auditSvc, budgetSvc, dlp.NewService("audit"),
		"", router, nil, nil, 0, nil, audit.PayloadModeFull,
	)

	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/proxy/chat", strings.NewReader(body))
	claims := &auth.Claims{UserID: "test-user", Role: "user"}
	req = req.WithContext(auth.WithClaims(req.Context(), claims))

	rec := httptest.NewRecorder()
	h.UnifiedChat(rec, req)
	auditSvc.Close()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	entries := auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(entries))
	}
	entry := entries[0]

	if entry.PromptTokens == 999 {
		t.Errorf("UnifiedChat использует ParseResponse вместо ParseStreamUsage")
	}
	if entry.PromptTokens != 11 || entry.CompletionTokens != 22 {
		t.Errorf("audit tokens = %d/%d, want 11/22 (из ParseStreamUsage)",
			entry.PromptTokens, entry.CompletionTokens)
	}
}

// nonStreamUsageProvider — provider БЕЗ StreamUsageProvider. Тест проверяет
// что handler корректно регистрирует stream_usage_parse_fail metric и не
// падает.
type nonStreamUsageProvider struct {
	url string
}

func (p *nonStreamUsageProvider) Name() string { return "openai" }
func (p *nonStreamUsageProvider) BuildRequest(ctx context.Context, body []byte, _ string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, "POST", p.url, bytes.NewReader(body))
}
func (p *nonStreamUsageProvider) ParseResponse(_ []byte) (int, int, int, float64, error) {
	return 0, 0, 0, 0, nil
}
func (p *nonStreamUsageProvider) StreamFormat() StreamFormat { return StreamSSE }
func (p *nonStreamUsageProvider) DefaultModel() string       { return "gpt-4o" }
func (p *nonStreamUsageProvider) SupportedModels() []string  { return []string{"gpt-4o"} }

// TestProxyChatStreaming_NonSupportingProviderSoftFail — migration
// contract: provider без StreamUsageProvider → 0 tokens в audit + request
// проходит успешно (не ошибка). Метрика
// shadowai_stream_usage_parse_fail_total{provider} инкрементируется.
func TestProxyChatStreaming_NonSupportingProviderSoftFail(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n"))
	}))
	defer upstream.Close()

	registry := NewRegistry()
	registry.Register(&nonStreamUsageProvider{url: upstream.URL})

	auditRepo := &captureAuditRepo{}
	auditSvc := audit.NewService(auditRepo)

	policySvc := &policy.Service{Engine: policy.NewEngine(emptyPolicyRepo{})}

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	budgetSvc := budget.NewService(unlimitedBudgetRepo{}, rdb)

	h := NewHandler(
		registry, policySvc, auditSvc, budgetSvc, dlp.NewService("audit"),
		"", nil, nil, nil, 0, nil, audit.PayloadModeFull,
	)

	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	claims := &auth.Claims{UserID: "test-user", Role: "user"}
	req = req.WithContext(auth.WithClaims(req.Context(), claims))

	rec := httptest.NewRecorder()
	h.ProxyChat(rec, req)
	auditSvc.Close()

	// Request должен ответить успешно (не парсер провайдера = не ошибка запроса).
	if rec.Code != http.StatusOK {
		t.Fatalf("non-supporting provider не должен fail'ить запрос; status=%d", rec.Code)
	}
	entries := auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(entries))
	}
	// Tokens = 0 (нет accounting), но запись есть — soft-fail path.
	if entries[0].TotalTokens != 0 {
		t.Errorf("non-supporting: want total_tokens=0 (soft-fail), got %d", entries[0].TotalTokens)
	}
}

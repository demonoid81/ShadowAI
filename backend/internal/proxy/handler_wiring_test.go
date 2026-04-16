package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"

	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/budget"
	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/firewall"
	"github.com/shadowai/backend/internal/policy"
)

// captureAuditRepo захватывает audit-записи в памяти, чтобы тест мог
// проверить, какие именно записи были сделаны handler'ом.
type captureAuditRepo struct {
	mu      sync.Mutex
	entries []*domain.AuditLog
}

func (c *captureAuditRepo) Insert(_ context.Context, entry *domain.AuditLog) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	clone := *entry
	c.entries = append(c.entries, &clone)
	return nil
}

func (c *captureAuditRepo) List(_ context.Context, _, _ int, _, _, _ string) ([]domain.AuditLog, int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]domain.AuditLog, len(c.entries))
	for i, e := range c.entries {
		out[i] = *e
	}
	return out, len(out), nil
}

func (c *captureAuditRepo) snapshot() []*domain.AuditLog {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*domain.AuditLog, len(c.entries))
	copy(out, c.entries)
	return out
}

// emptyPolicyRepo: policy engine без правил → всегда allowed.
type emptyPolicyRepo struct{}

func (emptyPolicyRepo) List(_ context.Context) ([]domain.PolicyRule, error) {
	return nil, nil
}

// unlimitedBudgetRepo: всегда "не найдено" → безлимит.
type unlimitedBudgetRepo struct{}

func (unlimitedBudgetRepo) GetByUserID(_ context.Context, _ string) (*domain.Budget, error) {
	return nil, io.EOF // любая ошибка → "no budget = unlimited"
}
func (unlimitedBudgetRepo) Upsert(_ context.Context, _ *domain.Budget) error { return nil }
func (unlimitedBudgetRepo) UpdateSpent(_ context.Context, _ string, _ float64, _ int) error {
	return nil
}

// flagInspector: всегда возвращает ActionFlag на request, ActionAllow на response.
type flagInspector struct{}

func (flagInspector) Name() string { return "test_flag" }
func (flagInspector) InspectRequest(_ context.Context, _ *firewall.Payload) (*firewall.Decision, error) {
	return &firewall.Decision{
		Action:   firewall.ActionFlag,
		Reason:   "test flag trigger",
		Severity: firewall.SeverityMedium,
	}, nil
}
func (flagInspector) InspectResponse(_ context.Context, _ *firewall.Payload) (*firewall.Decision, error) {
	return &firewall.Decision{Action: firewall.ActionAllow}, nil
}

// mockOpenAIProvider указывает на переопределяемый URL для теста.
type mockOpenAIProvider struct{ url string }

func (p *mockOpenAIProvider) Name() string { return "openai" }
func (p *mockOpenAIProvider) BuildRequest(ctx context.Context, body []byte, _ string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, "POST", p.url, bytes.NewReader(body))
}
func (p *mockOpenAIProvider) ParseResponse(_ []byte) (int, int, int, float64, error) {
	return 10, 5, 15, 0.0001, nil
}
func (p *mockOpenAIProvider) StreamFormat() StreamFormat   { return StreamSSE }
func (p *mockOpenAIProvider) DefaultModel() string         { return "gpt-4o" }
func (p *mockOpenAIProvider) SupportedModels() []string    { return []string{"gpt-4o"} }

// TestProxyChat_FirewallFlagPlusDLPSanitize_WiringIntegration — wiring-level тест
// на сценарий "firewall flag + DLP sanitize". Проверяет, что:
// 1. Запрос проходит через реальный ProxyChat handler
// 2. Записывается РОВНО одна финальная audit-запись (без промежуточных "warned")
// 3. PolicyAction = "sanitized", а не "warned" (фикс для потерянного sanitize)
func TestProxyChat_FirewallFlagPlusDLPSanitize_WiringIntegration(t *testing.T) {
	// 1. Mock upstream LLM
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"safe response"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
	}))
	defer upstream.Close()

	// 2. Провайдер и registry
	registry := NewRegistry()
	registry.Register(&mockOpenAIProvider{url: upstream.URL})

	// 3. Audit service с capture repo
	auditRepo := &captureAuditRepo{}
	auditSvc := audit.NewService(auditRepo)

	// 4. Policy service (без правил)
	policySvc := &policy.Service{Engine: policy.NewEngine(emptyPolicyRepo{})}

	// 5. Budget service с miniredis (безлимит через unlimitedBudgetRepo)
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	budgetSvc := budget.NewService(unlimitedBudgetRepo{}, rdb)

	// 6. DLP service в enforce — email триггерит sanitize
	dlpSvc := dlp.NewService("enforce")

	// 7. Firewall pipeline с always-flag inspector
	pipeline := firewall.NewPipeline()
	pipeline.Register(flagInspector{})

	// 8. Handler
	h := NewHandler(
		registry, policySvc, auditSvc, budgetSvc, dlpSvc,
		"", // allowedHosts — пусто, разрешаем всё
		nil, nil, nil,
		0,
		pipeline,
	)

	// 9. Запрос с email в content — DLP обязан санитизировать
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"please reply to user@example.com with a greeting"}]}`
	req := httptest.NewRequest("POST", "/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})

	// Встраиваем claims в контекст (обычно это делает AuthMiddleware)
	claims := &auth.Claims{UserID: "test-user", Email: "admin@example.com", Role: "user"}
	req = req.WithContext(auth.WithClaims(req.Context(), claims))

	rec := httptest.NewRecorder()

	// 10. Выполняем
	h.ProxyChat(rec, req)

	// 11. Закрываем audit для flush async-worker'а
	auditSvc.Close()

	// 12. Ассерты
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	entries := auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 audit entry, got %d:\n%+v", len(entries), entries)
	}

	entry := entries[0]
	if entry.PolicyAction != string(dlp.DLPActionSanitize) {
		t.Errorf("PolicyAction = %q, expected %q — firewall flag + DLP sanitize должен логироваться как sanitized, а не warned",
			entry.PolicyAction, dlp.DLPActionSanitize)
	}

	// Дополнительно: RequestBody должен быть санитизирован в audit (не содержать email)
	if strings.Contains(entry.RequestBody, "user@example.com") {
		t.Errorf("RequestBody содержит не санитизированный email: %s", entry.RequestBody)
	}

	// Проверим, что ответ дошёл до клиента
	var respJSON map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &respJSON); err != nil {
		t.Errorf("response не JSON: %v\nbody: %s", err, rec.Body.String())
	}
}

// TestUnifiedChat_FirewallFlagPlusDLPSanitize_WiringIntegration — wiring-level
// тест для UnifiedChat (/proxy/chat). Дублирует assertions провайдер-specific
// теста, но идёт через intelligent routing path с Router + fallback loop.
// UnifiedChat имеет собственные audit sites (handler.go:1199, 1351, 1468) —
// этот тест проверяет, что корреляция sanitized работает и там.
func TestUnifiedChat_FirewallFlagPlusDLPSanitize_WiringIntegration(t *testing.T) {
	// 1. Mock upstream LLM (отвечает на любой путь)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"safe response"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
	}))
	defer upstream.Close()

	// 2. Provider и registry
	registry := NewRegistry()
	registry.Register(&mockOpenAIProvider{url: upstream.URL})

	// 3. Audit capture
	auditRepo := &captureAuditRepo{}
	auditSvc := audit.NewService(auditRepo)

	// 4. Policy без правил
	policySvc := &policy.Service{Engine: policy.NewEngine(emptyPolicyRepo{})}

	// 5. Budget с miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	budgetSvc := budget.NewService(unlimitedBudgetRepo{}, rdb)

	// 6. DLP enforce
	dlpSvc := dlp.NewService("enforce")

	// 7. Firewall pipeline с always-flag
	pipeline := firewall.NewPipeline()
	pipeline.Register(flagInspector{})

	// 8. Router для UnifiedChat (без healthTracker, без fallback order)
	modelMapper := NewModelMapper(registry)
	router := NewRouter(registry, nil, modelMapper, StrategyCheapest, nil)

	// 9. Handler с router — это ключевое отличие от ProxyChat-теста
	h := NewHandler(
		registry, policySvc, auditSvc, budgetSvc, dlpSvc,
		"", router, nil, nil,
		0,
		pipeline,
	)

	// 10. Request к /proxy/chat
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"please reply to user@example.com with a greeting"}]}`
	req := httptest.NewRequest("POST", "/proxy/chat", strings.NewReader(body))
	claims := &auth.Claims{UserID: "test-user", Email: "admin@example.com", Role: "user"}
	req = req.WithContext(auth.WithClaims(req.Context(), claims))

	rec := httptest.NewRecorder()

	// 11. Exec
	h.UnifiedChat(rec, req)

	// 12. Flush audit
	auditSvc.Close()

	// 13. Ассерты
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	entries := auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 audit entry (без промежуточных warned), got %d:\n%+v", len(entries), entries)
	}

	entry := entries[0]
	if entry.PolicyAction != string(dlp.DLPActionSanitize) {
		t.Errorf("PolicyAction = %q, expected %q — UnifiedChat: firewall flag + DLP sanitize должен остаться sanitized",
			entry.PolicyAction, dlp.DLPActionSanitize)
	}

	if entry.Endpoint != "/proxy/chat" {
		t.Errorf("Endpoint = %q, expected /proxy/chat", entry.Endpoint)
	}

	if strings.Contains(entry.RequestBody, "user@example.com") {
		t.Errorf("RequestBody в audit содержит не санитизированный email: %s", entry.RequestBody)
	}
}

// TestProxyChat_Streaming_FirewallFlagPlusResponseDLPSanitize — wiring test
// для streaming-ветки ProxyChat. Покрывает отдельный audit site в streaming
// path (handler.go:454), где корреляция проверяется на другом коде.
//
// Сценарий: firewall flag на request + DLP sanitize на response (потому что
// upstream возвращает контент с email'ом, который триггерит sanitize).
func TestProxyChat_Streaming_FirewallFlagPlusResponseDLPSanitize(t *testing.T) {
	// Upstream возвращает SSE-like контент с email → DLP на response санитизирует
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"please contact support@example.com\"}}]}\n\ndata: [DONE]\n"))
	}))
	defer upstream.Close()

	registry := NewRegistry()
	registry.Register(&mockOpenAIProvider{url: upstream.URL})

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

	dlpSvc := dlp.NewService("enforce")

	pipeline := firewall.NewPipeline()
	pipeline.Register(flagInspector{})

	h := NewHandler(
		registry, policySvc, auditSvc, budgetSvc, dlpSvc,
		"", nil, nil, nil, 0, pipeline,
	)

	// stream: true активирует streaming branch
	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hello, need help"}]}`
	req := httptest.NewRequest("POST", "/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	claims := &auth.Claims{UserID: "test-user", Email: "admin@example.com", Role: "user"}
	req = req.WithContext(auth.WithClaims(req.Context(), claims))

	rec := httptest.NewRecorder()
	h.ProxyChat(rec, req)
	auditSvc.Close()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	entries := auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 audit entry (streaming path), got %d:\n%+v", len(entries), entries)
	}

	entry := entries[0]
	if entry.PolicyAction != string(dlp.DLPActionSanitize) {
		t.Errorf("streaming PolicyAction = %q, expected %q — firewall flag (request) + DLP sanitize (response) должен оставаться sanitized",
			entry.PolicyAction, dlp.DLPActionSanitize)
	}

	// Response в audit должен быть санитизирован
	if strings.Contains(entry.ResponseBody, "support@example.com") {
		t.Errorf("streaming ResponseBody содержит не санитизированный email: %s", entry.ResponseBody)
	}

	// Клиент получает санитизированный ответ (а не исходный с email)
	if strings.Contains(rec.Body.String(), "support@example.com") {
		t.Errorf("client response содержит не санитизированный email: %s", rec.Body.String())
	}
}

// TestUnifiedChat_Streaming_FirewallFlagPlusResponseDLPSanitize — аналогичный
// тест для UnifiedChat streaming path (handler.go:1351, 1379). Дублированная
// логика корреляции в unified streaming-ветке имеет свой независимый audit call.
func TestUnifiedChat_Streaming_FirewallFlagPlusResponseDLPSanitize(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"please contact support@example.com\"}}]}\n\ndata: [DONE]\n"))
	}))
	defer upstream.Close()

	registry := NewRegistry()
	registry.Register(&mockOpenAIProvider{url: upstream.URL})

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

	dlpSvc := dlp.NewService("enforce")

	pipeline := firewall.NewPipeline()
	pipeline.Register(flagInspector{})

	modelMapper := NewModelMapper(registry)
	router := NewRouter(registry, nil, modelMapper, StrategyCheapest, nil)

	h := NewHandler(
		registry, policySvc, auditSvc, budgetSvc, dlpSvc,
		"", router, nil, nil, 0, pipeline,
	)

	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hello, need help"}]}`
	req := httptest.NewRequest("POST", "/proxy/chat", strings.NewReader(body))
	claims := &auth.Claims{UserID: "test-user", Email: "admin@example.com", Role: "user"}
	req = req.WithContext(auth.WithClaims(req.Context(), claims))

	rec := httptest.NewRecorder()
	h.UnifiedChat(rec, req)
	auditSvc.Close()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	entries := auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 audit entry (unified streaming), got %d:\n%+v", len(entries), entries)
	}

	entry := entries[0]
	if entry.PolicyAction != string(dlp.DLPActionSanitize) {
		t.Errorf("unified streaming PolicyAction = %q, expected %q",
			entry.PolicyAction, dlp.DLPActionSanitize)
	}
	if entry.Endpoint != "/proxy/chat" {
		t.Errorf("Endpoint = %q, expected /proxy/chat", entry.Endpoint)
	}
	if strings.Contains(entry.ResponseBody, "support@example.com") {
		t.Errorf("unified streaming ResponseBody содержит не санитизированный email: %s", entry.ResponseBody)
	}
	if strings.Contains(rec.Body.String(), "support@example.com") {
		t.Errorf("client response содержит не санитизированный email: %s", rec.Body.String())
	}
}

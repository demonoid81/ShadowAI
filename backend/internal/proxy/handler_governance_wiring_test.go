//go:build enterprise

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/budget"
	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/governance"
	"github.com/shadowai/backend/internal/policy"
)

// govMemRepo — in-memory Repository для PR-G1 wiring-тестов.
type govMemRepo struct {
	policy *governance.Policy
}

func (r *govMemRepo) GetActive(ctx context.Context) (*governance.Policy, error) {
	return r.policy, nil
}
func (r *govMemRepo) Upsert(ctx context.Context, p *governance.Policy, actor string) (*governance.Policy, error) {
	r.policy = p
	return p, nil
}

// govCaptureRecorder — in-memory Recorder для проверки, что deny
// пишется в admin_event_logs.
type govCaptureRecorder struct {
	events []adminaudit.Event
}

func (c *govCaptureRecorder) Record(_ context.Context, ev adminaudit.Event) {
	c.events = append(c.events, ev)
}

// setupGovernanceProxy поднимает минимальный proxy.Handler с
// governanceSvc и mock recorder'ом. Остальные сервисы (firewall,
// cache, router) nil — фокус на enforcement точке. Используются
// существующие тестовые стабы (emptyPolicyRepo, captureAuditRepo,
// unlimitedBudgetRepo, mockOpenAIProvider) из handler_wiring_test.go.
func setupGovernanceProxy(t *testing.T, policyInRepo *governance.Policy) (*Handler, *govCaptureRecorder) {
	t.Helper()
	registry := NewRegistry()
	// mockOpenAIProvider c пустым url: governance-deny тестам
	// forward не нужен (short-circuit на 403). Для allow-теста
	// handler пойдёт на url — получит error, но admin audit мы
	// всё равно проверяем только на ОТСУТСТВИЕ policy_deny event.
	registry.Register(&mockOpenAIProvider{url: "http://127.0.0.1:1/unreachable"})
	policySvc := &policy.Service{Engine: policy.NewEngine(emptyPolicyRepo{})}
	auditSvc := audit.NewService(&captureAuditRepo{})
	budgetSvc := budget.NewService(unlimitedBudgetRepo{}, nil)
	dlpSvc := dlp.NewService("audit")

	rec := &govCaptureRecorder{}
	govSvc := governance.NewService(&govMemRepo{policy: policyInRepo})

	h := NewHandler(
		registry, policySvc, auditSvc, budgetSvc, dlpSvc,
		"", nil, nil, nil, 0, nil, audit.PayloadModeFull,
		govSvc, rec,
	)
	return h, rec
}

// TestProxyChat_GovernanceDeny_UnknownProvider — active policy
// запрещает провайдер openai (нет в Rules). Proxy должен вернуть
// 403 governance_deny и записать admin_event.
func TestProxyChat_GovernanceDeny_UnknownProvider(t *testing.T) {
	h, rec := setupGovernanceProxy(t, &governance.Policy{
		ID: "p-1", Mode: governance.ModeAllowlistStrict, IsActive: true,
		Rules: []governance.ProviderRule{
			// openai НЕ в allowlist — anthropic only
			{Provider: "anthropic", Models: []string{"claude-3-opus"}},
		},
	})

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/proxy/openai/v1/chat/completions",
		strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-1", Role: auth.RoleUser,
	}))
	w := httptest.NewRecorder()
	h.ProxyChat(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body unmarshal: %v", err)
	}
	if resp["code"] != governance.CodeUnknownProvider {
		t.Errorf("code = %v, want %q", resp["code"], governance.CodeUnknownProvider)
	}
	if resp["policy_id"] != "p-1" {
		t.Errorf("policy_id = %v, want p-1", resp["policy_id"])
	}

	// Admin event записан.
	if len(rec.events) != 1 {
		t.Fatalf("events = %d, want 1", len(rec.events))
	}
	ev := rec.events[0]
	if ev.Action != "policy_deny" || ev.Resource != "provider_model" {
		t.Errorf("action/resource = %q/%q", ev.Action, ev.Resource)
	}
	if ev.TargetID != "openai/gpt-4o" {
		t.Errorf("target_id = %q, want openai/gpt-4o", ev.TargetID)
	}
	if ev.Success {
		t.Error("success=true для deny event — ожидается false")
	}
	meta, _ := ev.Metadata.(map[string]any)
	if meta["code"] != governance.CodeUnknownProvider {
		t.Errorf("metadata.code = %v, want %q", meta["code"], governance.CodeUnknownProvider)
	}
}

// TestProxyChat_GovernanceDeny_UnknownModel — provider разрешён,
// модель — нет. Это ключевой use case для per-model governance.
func TestProxyChat_GovernanceDeny_UnknownModel(t *testing.T) {
	h, rec := setupGovernanceProxy(t, &governance.Policy{
		ID: "p-1", Mode: governance.ModeAllowlistStrict, IsActive: true,
		Rules: []governance.ProviderRule{
			// gpt-4o НЕ в allowlist — разрешена только gpt-4o-mini.
			// Provider совпадает, Model — нет; ожидаем CodeUnknownModel.
			{Provider: "openai", Models: []string{"gpt-4o-mini"}},
		},
	})

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/proxy/openai/v1/chat/completions",
		strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-1", Role: auth.RoleUser,
	}))
	w := httptest.NewRecorder()
	h.ProxyChat(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != governance.CodeUnknownModel {
		t.Errorf("code = %v, want %q", resp["code"], governance.CodeUnknownModel)
	}
	if len(rec.events) != 1 {
		t.Fatalf("events = %d, want 1 deny event", len(rec.events))
	}
}

// TestProxyChat_GovernanceAllow_PassesThroughToFirewall — happy path:
// active policy разрешает пару (openai, gpt-4). Governance НЕ
// короткозамыкает запрос; proxy продолжает обычный flow (в этом
// тесте firewall/cache nil → запрос пойдёт на fake провайдера).
//
// Критерий успеха: статус НЕ 403 с code=unknown_*. Конечный статус
// может быть любой (зависит от fake провайдера). Главное — admin
// audit НЕ записал deny event.
func TestProxyChat_GovernanceAllow_PassesThroughToFirewall(t *testing.T) {
	h, rec := setupGovernanceProxy(t, &governance.Policy{
		ID: "p-1", Mode: governance.ModeAllowlistStrict, IsActive: true,
		Rules: []governance.ProviderRule{
			{Provider: "openai", Models: []string{"gpt-4o"}},
		},
	})

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/proxy/openai/v1/chat/completions",
		bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-1", Role: auth.RoleUser,
	}))
	w := httptest.NewRecorder()
	h.ProxyChat(w, req)

	// Deny event НЕ должен быть записан.
	for _, ev := range rec.events {
		if ev.Action == "policy_deny" {
			t.Errorf("deny event recorded для allowed pair: %+v", ev)
		}
	}
	// Status НЕ 403 с governance-кодом.
	if w.Code == http.StatusForbidden {
		var resp map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if code, ok := resp["code"].(string); ok &&
			(code == governance.CodeUnknownProvider || code == governance.CodeUnknownModel) {
			t.Errorf("получен governance-deny для allowed pair: %+v", resp)
		}
	}
}

// TestProxyChat_GovernanceDisabled_AllowsAll — Mode=disabled →
// governance off, все провайдеры/модели проходят.
func TestProxyChat_GovernanceDisabled_AllowsAll(t *testing.T) {
	h, rec := setupGovernanceProxy(t, &governance.Policy{
		ID: "p-1", Mode: governance.ModeDisabled, IsActive: true,
		Rules: nil, // пустые правила при disabled не имеют значения
	})

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/proxy/openai/v1/chat/completions",
		bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-1", Role: auth.RoleUser,
	}))
	w := httptest.NewRecorder()
	h.ProxyChat(w, req)

	for _, ev := range rec.events {
		if ev.Action == "policy_deny" {
			t.Errorf("deny event recorded при Mode=disabled: %+v", ev)
		}
	}
}

// TestProxyChat_NilGovernanceSvc_Backward — старое поведение
// сохраняется, когда governance не сконфигурирован (nil svc).
// Это safety-net для dev/test деплоев и старых wiring-тестов.
func TestProxyChat_NilGovernanceSvc_Backward(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockOpenAIProvider{url: "http://127.0.0.1:1/unreachable"})
	policySvc := &policy.Service{Engine: policy.NewEngine(emptyPolicyRepo{})}
	auditSvc := audit.NewService(&captureAuditRepo{})
	budgetSvc := budget.NewService(unlimitedBudgetRepo{}, nil)
	dlpSvc := dlp.NewService("audit")

	h := NewHandler(
		registry, policySvc, auditSvc, budgetSvc, dlpSvc,
		"", nil, nil, nil, 0, nil, audit.PayloadModeFull,
		nil, nil, // nil governanceSvc, nil adminAudit
	)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/proxy/openai/v1/chat/completions",
		bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-1", Role: auth.RoleUser,
	}))
	w := httptest.NewRecorder()

	// Must not panic. Код 403/5xx приемлем (fake провайдер может
	// вернуть ошибку на upstream), главное — governance не вмешался.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panic: %v", r)
		}
	}()
	h.ProxyChat(w, req)
}

// TestProxyChat_RoleBased_AdminAllowedAnalystDenied — PR-G2 wiring.
// Проверяет, что claims.Role пробрасывается в Evaluate.
// Одна (provider, model) пара разрешена admin'у, но не analyst'у.
func TestProxyChat_RoleBased_AdminAllowedAnalystDenied(t *testing.T) {
	policy := &governance.Policy{
		ID: "p-1", Mode: governance.ModeAllowlistRoleBased, IsActive: true,
		RoleRules: []governance.RoleRule{
			{Role: "admin", Rules: []governance.ProviderRule{
				{Provider: "openai", Models: []string{"gpt-4o"}},
			}},
			{Role: "analyst", Rules: []governance.ProviderRule{
				{Provider: "openai", Models: []string{"gpt-4o-mini"}},
			}},
		},
	}

	// Analyst → privileged model → deny.
	h, rec := setupGovernanceProxy(t, policy)
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/proxy/openai/v1/chat/completions",
		bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-analyst", Role: auth.RoleAnalyst,
	}))
	w := httptest.NewRecorder()
	h.ProxyChat(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("analyst/gpt-4o status = %d, want 403, body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != governance.CodeUnknownModel {
		t.Errorf("code = %v, want unknown_model", resp["code"])
	}
	if len(rec.events) != 1 || rec.events[0].Action != "policy_deny" {
		t.Errorf("events = %+v, want 1 policy_deny", rec.events)
	}

	// Admin той же модели → allow (deny event НЕ создаётся).
	h2, rec2 := setupGovernanceProxy(t, policy)
	req2 := httptest.NewRequest(http.MethodPost, "/proxy/openai/v1/chat/completions",
		bytes.NewBufferString(body))
	req2 = mux.SetURLVars(req2, map[string]string{"provider": "openai"})
	req2 = req2.WithContext(auth.WithClaims(req2.Context(), &auth.Claims{
		UserID: "u-admin", Role: auth.RoleAdmin,
	}))
	w2 := httptest.NewRecorder()
	h2.ProxyChat(w2, req2)

	for _, ev := range rec2.events {
		if ev.Action == "policy_deny" {
			t.Errorf("admin/gpt-4o получил deny event: %+v", ev)
		}
	}
}

// TestProxyChat_RoleBased_UnknownRoleDenied — role caller'а
// отсутствует в RoleRules → 403 + code=unknown_role.
func TestProxyChat_RoleBased_UnknownRoleDenied(t *testing.T) {
	policy := &governance.Policy{
		ID: "p-1", Mode: governance.ModeAllowlistRoleBased, IsActive: true,
		RoleRules: []governance.RoleRule{
			{Role: "admin", Rules: []governance.ProviderRule{
				{Provider: "openai", Models: []string{"gpt-4o"}},
			}},
		},
	}
	h, rec := setupGovernanceProxy(t, policy)
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/proxy/openai/v1/chat/completions",
		bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-user", Role: "user", // не в RoleRules
	}))
	w := httptest.NewRecorder()
	h.ProxyChat(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("unknown role status = %d, want 403", w.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != governance.CodeUnknownRole {
		t.Errorf("code = %v, want unknown_role", resp["code"])
	}
	if len(rec.events) != 1 || rec.events[0].Action != "policy_deny" {
		t.Errorf("events = %+v", rec.events)
	}
}

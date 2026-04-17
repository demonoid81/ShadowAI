package proxy

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/shadowai/backend/internal/firewall"
	"github.com/shadowai/backend/internal/policy"
)

// shadowBlockingInspector — test stub: в enforce вернул бы Block,
// но pipeline в shadow-режиме должен это НЕ исполнить, а лишь
// записать наблюдение в audit_logs.shadow_decisions_json.
type shadowBlockingInspector struct{}

func (shadowBlockingInspector) Name() string { return "shadow_pi_stub" }
func (shadowBlockingInspector) InspectRequest(_ context.Context, _ *firewall.Payload) (*firewall.Decision, error) {
	return &firewall.Decision{
		Action:   firewall.ActionBlock,
		Reason:   "shadow-blocked-for-observability",
		Severity: firewall.SeverityHigh,
	}, nil
}
func (shadowBlockingInspector) InspectResponse(_ context.Context, _ *firewall.Payload) (*firewall.Decision, error) {
	return &firewall.Decision{Action: firewall.ActionAllow}, nil
}

// TestProxyChat_ShadowInspector_DoesNotBlock_WritesShadowDecisions —
// PR-4 core wiring:
//
//  1. Ранний инспектор shadow_pi_stub в ModeShadow хочет Block.
//  2. Handler должен НЕ блокировать: status 200, response от upstream.
//  3. Audit row должен содержать ShadowDecisionsJSON с наблюдением
//     ("inspector":"shadow_pi_stub","action":"block",...).
//  4. PolicyAction остаётся фактическим итогом ("allowed"), а не
//     перегружен shadow-значением.
func TestProxyChat_ShadowInspector_DoesNotBlock_WritesShadowDecisions(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`))
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
	dlpSvc := dlp.NewService("off")

	// Pipeline с ОДНИМ инспектором в shadow-режиме. Это гарантирует,
	// что если shadow не уважает контракт (т.е. реально блокирует),
	// тест завалится на HTTP-уровне.
	modes := firewall.NewInspectorModes(firewall.ModeEnforce)
	modes.Overrides["shadow_pi_stub"] = firewall.ModeShadow

	pipeline := firewall.NewPipelineWithModes(modes)
	pipeline.Register(shadowBlockingInspector{})

	h := NewHandler(
		registry, policySvc, auditSvc, budgetSvc, dlpSvc,
		"", nil, nil, nil, 0, pipeline,
	)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	claims := &auth.Claims{UserID: "test-user", Email: "u@e.com", Role: "user"}
	req = req.WithContext(auth.WithClaims(req.Context(), claims))

	rec := httptest.NewRecorder()
	h.ProxyChat(rec, req)
	auditSvc.Close()

	// (2) shadow не должен блокировать.
	if rec.Code != http.StatusOK {
		t.Fatalf("shadow inspector заблокировал request: status = %d, body = %s",
			rec.Code, rec.Body.String())
	}

	entries := auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 audit entry, got %d", len(entries))
	}
	entry := entries[0]

	// (4) PolicyAction остаётся фактическим итогом — allowed.
	if entry.PolicyAction == "blocked" {
		t.Errorf("PolicyAction = %q: shadow не должен перегружать фактический итог запроса",
			entry.PolicyAction)
	}

	// (3) ShadowDecisionsJSON не пустой и содержит ожидаемое наблюдение.
	if entry.ShadowDecisionsJSON == "" {
		t.Fatal("ShadowDecisionsJSON пустой — shadow-наблюдение не попало в audit row")
	}

	var shadows []firewall.ShadowDecision
	if err := json.Unmarshal([]byte(entry.ShadowDecisionsJSON), &shadows); err != nil {
		t.Fatalf("ShadowDecisionsJSON не парсится: %v (raw: %s)", err, entry.ShadowDecisionsJSON)
	}
	if len(shadows) != 1 {
		t.Fatalf("len(shadows) = %d, want 1 (ровно одно наблюдение от shadow_pi_stub)", len(shadows))
	}
	sd := shadows[0]
	if sd.Inspector != "shadow_pi_stub" {
		t.Errorf("shadow.Inspector = %q, want shadow_pi_stub", sd.Inspector)
	}
	if sd.Action != firewall.ActionBlock {
		t.Errorf("shadow.Action = %q, want block (оригинальное shadow-решение)", sd.Action)
	}
	if sd.Severity != firewall.SeverityHigh {
		t.Errorf("shadow.Severity = %q, want high", sd.Severity)
	}
}

// TestProxyChat_EnforceInspector_NoShadowInAudit — контроль: запрос,
// в котором ни один инспектор не работает в shadow-режиме, даёт
// audit row БЕЗ shadow_decisions (пустая строка → NULL в Postgres).
//
// Это гарантирует, что мы не шлём в БД "[]" для обычных запросов —
// пусто и NULL различимы, что важно для dashboards вида
//   SELECT count(*) FROM audit_logs WHERE shadow_decisions_json IS NOT NULL.
func TestProxyChat_EnforceInspector_NoShadowInAudit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`))
	}))
	defer upstream.Close()

	registry := NewRegistry()
	registry.Register(&mockOpenAIProvider{url: upstream.URL})
	auditRepo := &captureAuditRepo{}
	auditSvc := audit.NewService(auditRepo)
	policySvc := &policy.Service{Engine: policy.NewEngine(emptyPolicyRepo{})}

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	// Pipeline пустой (или только allow-инспекторы) — shadow не сработает.
	pipeline := firewall.NewPipeline()

	h := NewHandler(
		registry, policySvc, auditSvc,
		budget.NewService(unlimitedBudgetRepo{}, rdb),
		dlp.NewService("off"),
		"", nil, nil, nil, 0, pipeline,
	)

	req := httptest.NewRequest("POST", "/proxy/openai/v1/chat/completions",
		bytes.NewReader([]byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	req = req.WithContext(auth.WithClaims(req.Context(),
		&auth.Claims{UserID: "u", Email: "e@e.com", Role: "user"}))

	rec := httptest.NewRecorder()
	h.ProxyChat(rec, req)
	auditSvc.Close()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	entries := auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(entries))
	}
	if entries[0].ShadowDecisionsJSON != "" {
		t.Errorf("ShadowDecisionsJSON = %q, want empty — shadow никто не запускал",
			entries[0].ShadowDecisionsJSON)
	}
}

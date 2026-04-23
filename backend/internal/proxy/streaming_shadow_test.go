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
	"github.com/shadowai/backend/internal/firewall"
	"github.com/shadowai/backend/internal/policy"
)

// TestProxyChat_ShadowMode_NoClientBehaviorChange — PR-F7.4 core
// invariant: STREAMING_MODE=shadow не должен менять client-visible
// behavior. Client получает ровно те же bytes, что и в buffered mode.
func TestProxyChat_ShadowMode_NoClientBehaviorChange(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write(canonicalOpenAIStream)
	}))
	defer upstream.Close()

	registry := NewRegistry()
	registry.Register(&mockOpenAIProvider{url: upstream.URL})

	auditRepo := &captureAuditRepo{}
	auditSvc := audit.NewService(auditRepo)

	mr, _ := miniredis.Run()
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	h := NewHandler(
		registry,
		&policy.Service{Engine: policy.NewEngine(emptyPolicyRepo{})},
		auditSvc, budget.NewService(unlimitedBudgetRepo{}, rdb),
		dlp.NewService("enforce"),
		"", nil, nil, nil, 0, firewall.NewPipeline(),
		audit.PayloadModeFull,
		nil, nil,
	)
	h.SetStreamingMode("shadow") // shadow = buffered path + parallel compare

	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{UserID: "u", Role: "user"}))

	rec := httptest.NewRecorder()
	h.ProxyChat(rec, req)
	auditSvc.Close()

	// Client получает 200 + полный stream байт-в-байт (buffered truth).
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !bytes.Equal(rec.Body.Bytes(), canonicalOpenAIStream) {
		t.Errorf("shadow mode изменил client body:\nwant %q\n got %q",
			canonicalOpenAIStream, rec.Body.Bytes())
	}

	// Audit запись: buffered truth (не shadow result).
	entries := auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1 (buffered truth only)", len(entries))
	}
	// Shadow mode пишет buffered outcomes, не shadow-specific.
	// Outcome должен быть stream_completed (clean stream).
	if entries[0].Outcome != OutcomeStreamCompleted {
		t.Errorf("Outcome = %q, want %q", entries[0].Outcome, OutcomeStreamCompleted)
	}
}

// TestRunShadowCompare_MatchOnCleanStream — чистый stream без
// inspector'ов → buffered и incremental должны совпасть (match=true).
func TestRunShadowCompare_MatchOnCleanStream(t *testing.T) {
	h := &Handler{
		streamingMode: "shadow",
	}

	result := h.runShadowCompare(
		context.Background(),
		canonicalOpenAIStream,
		"openai",
		"gpt-4o", "u-test",
		&mockOpenAIProvider{}, // provider (no ParseStreamUsage → soft-fail)
		OutcomeStreamCompleted, "allowed", UsageSourceNone,
	)

	if !result.Match {
		t.Errorf("expected match on clean stream; mismatches: %+v", result.Mismatches)
	}
	if len(result.Mismatches) != 0 {
		t.Errorf("unexpected mismatches: %+v", result.Mismatches)
	}
}

// TestRunShadowCompare_CapabilityFallback_ReportsMetric — если
// capability говорит buffered_fallback (CM+judge), shadow должен
// сообщить об этом через FallbackReason, не паниковать.
func TestRunShadowCompare_CapabilityFallback_ReportsMetric(t *testing.T) {
	judge := firewall.NewJudge(firewall.JudgeConfig{Enabled: true, Provider: "test"})
	cm := firewall.NewContentModerationInspector(firewall.ContentModerationConfig{
		Enabled: true, JudgeThreshold: 0.3,
	}, judge)
	pipeline := firewall.NewPipeline()
	pipeline.Register(cm)

	h := &Handler{
		streamingMode:       "shadow",
		streamingCapability: DecideStreamingCapability(pipeline), // → fallback
	}

	result := h.runShadowCompare(
		context.Background(),
		canonicalOpenAIStream,
		"openai", "gpt-4o", "u-test",
		&mockOpenAIProvider{},
		OutcomeStreamBufferedFallback, "allowed", UsageSourceNone,
	)

	if result.FallbackReason != FallbackReasonJudgeInspector {
		t.Errorf("FallbackReason = %q, want %q", result.FallbackReason, FallbackReasonJudgeInspector)
	}
	// Buffered сам отдал stream_buffered_fallback → этот match ожидаем.
	if !result.Match {
		t.Errorf("CM+judge fallback: buffered и shadow оба знают о fallback → Match должен быть true")
	}
}

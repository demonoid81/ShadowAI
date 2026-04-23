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

// buildF72Handler — минимальный Handler для F7.2 end-to-end тестов.
// Позволяет конфигурировать streamingMode + firewallPipeline +
// upstream bytes.
type f72Harness struct {
	h          *Handler
	auditRepo  *captureAuditRepo
	flushAudit func()
	cleanup    func()
}

func buildF72Handler(t *testing.T, upstreamBody []byte, pipeline *firewall.Pipeline, streamingMode string) f72Harness {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write(upstreamBody)
	}))

	registry := NewRegistry()
	registry.Register(&mockOpenAIProvider{url: upstream.URL})

	auditRepo := &captureAuditRepo{}
	auditSvc := audit.NewService(auditRepo)

	mr, _ := miniredis.Run()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	h := NewHandler(
		registry,
		&policy.Service{Engine: policy.NewEngine(emptyPolicyRepo{})},
		auditSvc, budget.NewService(unlimitedBudgetRepo{}, rdb),
		dlp.NewService("enforce"),
		"", nil, nil, nil, 0, pipeline,
		audit.PayloadModeFull,
		nil, nil,
	)
	h.SetStreamingMode(streamingMode)

	return f72Harness{
		h:          h,
		auditRepo:  auditRepo,
		flushAudit: func() { auditSvc.Close() },
		cleanup: func() {
			upstream.Close()
			rdb.Close()
			mr.Close()
		},
	}
}

func doF72Stream(h *Handler, t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{UserID: "u", Role: "user"}))
	rec := httptest.NewRecorder()
	h.ProxyChat(rec, req)
	return rec
}

// TestProxyChat_Incremental_MidstreamBlock_ClientGetsErrorFrame —
// inspector blocks на первом delta; client получает частичный
// stream + SSE error frame; audit помечен streaming_blocked_midflight.
func TestProxyChat_Incremental_MidstreamBlock_ClientGetsErrorFrame(t *testing.T) {
	pipeline := firewall.NewPipeline()
	// containsBlockInspector триггерит block, когда в window
	// появляется "BLOCK_ME". Упакуем это в upstream-stream.
	pipeline.Register(containsBlockInspector{needle: "BLOCK_ME"})

	upstream := []byte(
		`data: {"choices":[{"delta":{"content":"please BLOCK_ME now"}}]}` + "\n\n" +
			`data: [DONE]` + "\n\n")

	th := buildF72Handler(t, upstream, pipeline, "incremental")
	defer th.cleanup()

	rec := doF72Stream(th.h, t)
	th.flushAudit()

	// Client получил 200 + partial stream. Реверсировать statusCode
	// в incremental mode нельзя, так что 200 — ожидаемо. Главное:
	// audit помечен block и stream содержит terminal error frame
	// (событие 'error' от openai-compat emitter'а).
	if rec.Code != http.StatusOK {
		t.Fatalf("client status = %d, want 200 (emit уже начат)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "event: error") {
		t.Errorf("client body не содержит SSE error frame: %q", rec.Body.String())
	}

	entries := th.auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.PolicyAction != PolicyActionStreamingBlockedMidflight {
		t.Errorf("PolicyAction = %q, want %q", e.PolicyAction, PolicyActionStreamingBlockedMidflight)
	}
	if e.StatusCode != http.StatusForbidden {
		t.Errorf("audit StatusCode = %d, want 403", e.StatusCode)
	}
}

// TestProxyChat_Incremental_Flagged_AuditMarker — flag не блокирует
// stream, но помечает audit.
func TestProxyChat_Incremental_Flagged_AuditMarker(t *testing.T) {
	pipeline := firewall.NewPipeline()
	pipeline.Register(alwaysFlagResponseInspector{})

	upstream := []byte(
		`data: {"choices":[{"delta":{"content":"hello"}}]}` + "\n\n" +
			`data: [DONE]` + "\n\n")

	th := buildF72Handler(t, upstream, pipeline, "incremental")
	defer th.cleanup()

	rec := doF72Stream(th.h, t)
	th.flushAudit()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	// Client получил полный stream (flag не прерывает).
	if !bytes.Equal(rec.Body.Bytes(), upstream) {
		t.Errorf("flag должен пропустить stream identity; got %q", rec.Body.Bytes())
	}

	entries := th.auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d", len(entries))
	}
	if entries[0].PolicyAction != PolicyActionStreamingFlagged {
		t.Errorf("PolicyAction = %q, want %q", entries[0].PolicyAction, PolicyActionStreamingFlagged)
	}
}

// TestProxyChat_Incremental_CMJudge_BufferedFallback — capability
// check на wire-time говорит fallback, stream идёт через buffered
// и audit'ируется с streaming_buffered_fallback marker'ом.
func TestProxyChat_Incremental_CMJudge_BufferedFallback(t *testing.T) {
	// CM inspector с judge.Enabled=true → capability = fallback.
	judge := firewall.NewJudge(firewall.JudgeConfig{Enabled: true, Provider: "test"})
	cm := firewall.NewContentModerationInspector(firewall.ContentModerationConfig{
		Enabled:        true,
		JudgeThreshold: 0.3,
	}, judge)
	pipeline := firewall.NewPipeline()
	pipeline.Register(cm)

	upstream := []byte(
		`data: {"choices":[{"delta":{"content":"benign"}}]}` + "\n\n" +
			`data: [DONE]` + "\n\n")

	th := buildF72Handler(t, upstream, pipeline, "incremental")
	defer th.cleanup()

	rec := doF72Stream(th.h, t)
	th.flushAudit()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	// Buffered fallback path пишет body байт-в-байт (heuristic-only CM
	// на benign тексте не блокирует).
	if !bytes.Equal(rec.Body.Bytes(), upstream) {
		t.Errorf("fallback должен отдать стрим без модификации; got %q", rec.Body.Bytes())
	}

	entries := th.auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d", len(entries))
	}
	if entries[0].PolicyAction != PolicyActionStreamingBufferedFallback {
		t.Errorf("PolicyAction = %q, want %q",
			entries[0].PolicyAction, PolicyActionStreamingBufferedFallback)
	}
}

// TestProxyChat_Incremental_CleanStream_AllowAudit — стрим без
// firewall-сигналов не должен получить F7.2 markers (block/flagged/
// buffered_fallback).
func TestProxyChat_Incremental_CleanStream_AllowAudit(t *testing.T) {
	pipeline := firewall.NewPipeline() // empty — no inspectors

	upstream := []byte(
		`data: {"choices":[{"delta":{"content":"hi"}}]}` + "\n\n" +
			`data: [DONE]` + "\n\n")

	th := buildF72Handler(t, upstream, pipeline, "incremental")
	defer th.cleanup()

	rec := doF72Stream(th.h, t)
	th.flushAudit()

	entries := th.auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d", len(entries))
	}
	bad := map[string]bool{
		PolicyActionStreamingBlockedMidflight: true,
		PolicyActionStreamingFlagged:          true,
		PolicyActionStreamingBufferedFallback: true,
	}
	if bad[entries[0].PolicyAction] {
		t.Errorf("clean stream получил F7.2 marker %q, ожидался обычный allow",
			entries[0].PolicyAction)
	}
	// Client получает full stream.
	if !bytes.Equal(rec.Body.Bytes(), upstream) {
		t.Errorf("clean incremental stream не byte-identical")
	}
}

// Reference (избегает "imported and not used" для context).
var _ = context.Background

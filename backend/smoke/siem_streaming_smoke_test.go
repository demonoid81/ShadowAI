//go:build enterprise && smoke

// PR-O3.1.2: SIEM async delivery + streaming proxy smoke scenarios.
// Покрывает runtime path, которые не проверялись в предыдущих O3 smoke:
//   - SIEM AsyncBatchRecorder: batch delivery, retry, fail-open
//   - SIEM backpressure: drop policy (не deadlock, drop metric растёт)
//   - Streaming buffered: legacy path, stream_completed в audit
//   - Streaming incremental: bytes identity, correct audit outcome
//   - Streaming fallback: stream_buffered_fallback + fallback_reason
//
// Streaming тесты используют mock audit repo (паттерн из internal/proxy),
// а не real PG — audit write path уже покрыт WORM smoke; здесь цель —
// проверить streaming wiring и SSE bytes identity.
//
// Запуск:
//
//	cd backend && go test -tags 'enterprise smoke' ./smoke/... -run 'TestSmoke_(SIEM|Streaming)' -v -count=1 -timeout 15m
package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/budget"
	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/firewall"
	"github.com/shadowai/backend/internal/policy"
	"github.com/shadowai/backend/internal/proxy"
	"github.com/shadowai/backend/internal/siem"
)

// smokeOpenAISSE is a minimal OpenAI-compatible SSE stream for smoke tests.
var smokeOpenAISSE = []byte(
	"data: {\"id\":\"s-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"s-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"s-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: [DONE]\n\n")

// ---------------------------------------------------------------------------
// O3.1.2.A — SIEM async batch delivery + retry
// ---------------------------------------------------------------------------

func TestSmoke_SIEM_AsyncBatchDelivery(t *testing.T) {
	var receivedEnvs atomic.Int32
	var sinkCalls atomic.Int32

	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := sinkCalls.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503 → retry
			return
		}
		body, _ := io.ReadAll(r.Body)
		var envs []map[string]any
		if err := json.Unmarshal(body, &envs); err != nil {
			t.Errorf("SIEM batch is not JSON array: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		receivedEnvs.Add(int32(len(envs)))
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	httpRec := siem.NewHTTPRecorder(sink.URL, "test-token", 2*time.Second, false)
	rec := siem.NewAsyncBatchRecorder(httpRec, siem.AsyncBatchOptions{
		QueueSize:     20,
		BatchSize:     3,
		FlushInterval: 80 * time.Millisecond,
		MaxRetries:    3,
		RetryBase:     10 * time.Millisecond,
		DropPolicy:    siem.DropOldest,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go rec.Run(ctx)

	start := time.Now()
	for i := 0; i < 3; i++ {
		rec.Record(context.Background(), siem.Event{Action: "smoke_event", Resource: "audit_logs", Success: true})
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("Record() blocked for %v — must be non-blocking", elapsed)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if receivedEnvs.Load() == 3 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if got := receivedEnvs.Load(); got != 3 {
		t.Errorf("SIEM delivered %d events, want 3 (after retry); sink_calls=%d", got, sinkCalls.Load())
	}
	t.Logf("smoke/siem-delivery: envelopes=%d sink_calls=%d", receivedEnvs.Load(), sinkCalls.Load())
}

// ---------------------------------------------------------------------------
// O3.1.2.B — SIEM backpressure
// ---------------------------------------------------------------------------

func TestSmoke_SIEM_Backpressure(t *testing.T) {
	blocker := make(chan struct{})
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocker
		io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() {
		close(blocker)
		sink.Close()
	})

	httpRec := siem.NewHTTPRecorder(sink.URL, "", 5*time.Second, false)
	rec := siem.NewAsyncBatchRecorder(httpRec, siem.AsyncBatchOptions{
		QueueSize:     2,
		BatchSize:     10,
		FlushInterval: 50 * time.Millisecond,
		MaxRetries:    1,
		DropPolicy:    siem.DropOldest,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rec.Run(ctx)

	droppedBefore := prometheusCounterSum("shadowai_siem_dropped_total")

	start := time.Now()
	for i := 0; i < 10; i++ {
		rec.Record(context.Background(), siem.Event{Action: "overflow", Resource: "test", Success: true})
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("Record() blocked under backpressure for %v", elapsed)
	}

	time.Sleep(200 * time.Millisecond)

	droppedAfter := prometheusCounterSum("shadowai_siem_dropped_total")
	if droppedAfter <= droppedBefore {
		t.Errorf("drop metric did not increase: before=%.0f after=%.0f", droppedBefore, droppedAfter)
	}
	t.Logf("smoke/siem-backpressure: dropped=+%.0f", droppedAfter-droppedBefore)
}

// ---------------------------------------------------------------------------
// O3.1.2.C — Streaming buffered
// ---------------------------------------------------------------------------

func TestSmoke_Streaming_Buffered(t *testing.T) {
	h, repo, cleanup := buildSmokeStreamingHandler(t, smokeOpenAISSE, "buffered", firewall.NewPipeline())
	defer cleanup()

	rr := doSmokeProxyChat(h, t)
	if rr.Code != http.StatusOK {
		t.Fatalf("buffered: status=%d body=%q", rr.Code, limitStr(rr.Body.String(), 300))
	}
	if !strings.Contains(rr.Body.String(), "data:") {
		t.Errorf("buffered: SSE data missing: %q", limitStr(rr.Body.String(), 200))
	}

	time.Sleep(60 * time.Millisecond) // audit.Service async flush
	logs := repo.Snapshot()
	if len(logs) == 0 {
		t.Error("buffered: no audit record written")
	} else {
		// Buffered path with a short stream completes normally.
		if logs[0].Outcome != proxy.OutcomeStreamCompleted {
			t.Errorf("buffered: outcome=%q want stream_completed", logs[0].Outcome)
		}
		t.Logf("smoke/streaming-buffered: outcome=%q usage_source=%q", logs[0].Outcome, logs[0].UsageSource)
	}
}

// ---------------------------------------------------------------------------
// O3.1.2.D — Streaming incremental
// ---------------------------------------------------------------------------

func TestSmoke_Streaming_Incremental(t *testing.T) {
	h, repo, cleanup := buildSmokeStreamingHandler(t, smokeOpenAISSE, "incremental", firewall.NewPipeline())
	defer cleanup()

	rr := doSmokeProxyChat(h, t)
	if rr.Code != http.StatusOK {
		t.Fatalf("incremental: status=%d body=%q", rr.Code, limitStr(rr.Body.String(), 300))
	}
	// Bytes identity: incremental transport must forward upstream bytes verbatim.
	got := rr.Body.Bytes()
	if !bytes.Equal(got, smokeOpenAISSE) {
		t.Errorf("incremental: bytes identity violated\nwant len=%d got len=%d\nwant=%q\ngot =%q",
			len(smokeOpenAISSE), len(got), smokeOpenAISSE, got)
	}

	time.Sleep(60 * time.Millisecond)
	logs := repo.Snapshot()
	if len(logs) == 0 {
		t.Error("incremental: no audit record")
	} else {
		if logs[0].Outcome != proxy.OutcomeStreamCompleted {
			t.Errorf("incremental: outcome=%q want stream_completed", logs[0].Outcome)
		}
		t.Logf("smoke/streaming-incremental: outcome=%q usage_source=%q", logs[0].Outcome, logs[0].UsageSource)
	}
}

// ---------------------------------------------------------------------------
// O3.1.2.E — Streaming fallback (CM+judge → buffered_fallback)
// ---------------------------------------------------------------------------

func TestSmoke_Streaming_Fallback(t *testing.T) {
	judge := firewall.NewJudge(firewall.JudgeConfig{Enabled: true, Provider: "test"})
	pipeline := firewall.NewPipeline()
	pipeline.Register(firewall.NewContentModerationInspector(firewall.ContentModerationConfig{
		Enabled: true, HeuristicThreshold: 0.7, JudgeThreshold: 0.3,
	}, judge))

	h, repo, cleanup := buildSmokeStreamingHandler(t, smokeOpenAISSE, "incremental", pipeline)
	defer cleanup()

	rr := doSmokeProxyChat(h, t)
	if rr.Code != http.StatusOK {
		t.Fatalf("fallback: status=%d body=%q", rr.Code, limitStr(rr.Body.String(), 300))
	}

	time.Sleep(60 * time.Millisecond)
	logs := repo.Snapshot()
	if len(logs) == 0 {
		t.Error("fallback: no audit record")
		return
	}
	if logs[0].Outcome != proxy.OutcomeStreamBufferedFallback {
		t.Errorf("fallback: outcome=%q want stream_buffered_fallback", logs[0].Outcome)
	}
	if logs[0].FallbackReason != proxy.FallbackReasonJudgeInspector {
		t.Errorf("fallback: fallback_reason=%q want judge_inspector", logs[0].FallbackReason)
	}
	t.Logf("smoke/streaming-fallback: outcome=%q fallback_reason=%q", logs[0].Outcome, logs[0].FallbackReason)
}

// ---------------------------------------------------------------------------
// Streaming handler builder
// ---------------------------------------------------------------------------

func buildSmokeStreamingHandler(
	t *testing.T,
	upstreamBody []byte,
	streamingMode string,
	pipeline *firewall.Pipeline,
) (*proxy.Handler, *smokeCapAuditRepo, func()) {
	t.Helper()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write(upstreamBody)
	}))

	registry := proxy.NewRegistry()
	registry.Register(&smokeOAIProvider{url: upstream.URL})

	auditRepo := &smokeCapAuditRepo{}
	auditSvc := audit.NewService(auditRepo)

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	budgetSvc := budget.NewService(smokeUnlimitedBudgetRepo{}, rdb)
	policySvc := &policy.Service{Engine: policy.NewEngine(smokeEmptyPolicyRepo{})}
	dlpSvc := dlp.NewService("enforce")

	h := proxy.NewHandler(
		registry, policySvc, auditSvc, budgetSvc, dlpSvc,
		"", nil, nil, nil, 0,
		pipeline, audit.PayloadModeRedacted,
		nil, nil,
	)
	h.SetStreamingMode(streamingMode)

	cleanup := func() {
		auditSvc.Close()
		upstream.Close()
		rdb.Close()
		mr.Close()
	}
	return h, auditRepo, cleanup
}

func doSmokeProxyChat(h *proxy.Handler, t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest("POST", "/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "smoke-user", Email: "smoke@test.local", Role: auth.RoleUser,
	}))
	rr := httptest.NewRecorder()
	h.ProxyChat(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Mock types
// ---------------------------------------------------------------------------

type smokeOAIProvider struct{ url string }

func (p *smokeOAIProvider) Name() string { return "openai" }
func (p *smokeOAIProvider) BuildRequest(_ context.Context, body []byte, _ string) (*http.Request, error) {
	return http.NewRequest("POST", p.url, bytes.NewReader(body))
}
func (p *smokeOAIProvider) ParseResponse(_ []byte) (int, int, int, float64, error) {
	return 5, 5, 10, 0.001, nil
}
func (p *smokeOAIProvider) StreamFormat() proxy.StreamFormat { return proxy.StreamSSE }
func (p *smokeOAIProvider) DefaultModel() string             { return "gpt-4o" }
func (p *smokeOAIProvider) SupportedModels() []string        { return []string{"gpt-4o"} }
func (p *smokeOAIProvider) ParseStreamUsage(_ []byte, _ string) (proxy.StreamUsage, error) {
	return proxy.StreamUsage{Found: true, TotalTokens: 10, CostUSD: 0.001}, nil
}

type smokeCapAuditRepo struct {
	mu      sync.Mutex
	entries []*domain.AuditLog
}

func (r *smokeCapAuditRepo) Insert(_ context.Context, e *domain.AuditLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *e
	r.entries = append(r.entries, &clone)
	return nil
}
func (r *smokeCapAuditRepo) Snapshot() []*domain.AuditLog {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.AuditLog, len(r.entries))
	copy(out, r.entries)
	return out
}
func (r *smokeCapAuditRepo) List(_ context.Context, _, _ int, _, _, _, _ string) ([]domain.AuditLog, int, error) {
	return nil, 0, nil
}
func (r *smokeCapAuditRepo) PurgeOlderThan(_ context.Context, _ time.Time, _ int) (int, error) {
	return 0, nil
}
func (r *smokeCapAuditRepo) PurgeOlderThanExcept(_ context.Context, _ time.Time, _ int, _ []string) (int, error) {
	return 0, nil
}
func (r *smokeCapAuditRepo) RecordPurgeRun(_ context.Context, _ time.Time, _ int, _ string) error {
	return nil
}
func (r *smokeCapAuditRepo) LastPurgeRun(_ context.Context, _ string) (*domain.PurgeRun, error) {
	return nil, nil
}
func (r *smokeCapAuditRepo) TotalRowsPurged(_ context.Context, _ string) (int, error) { return 0, nil }

type smokeUnlimitedBudgetRepo struct{}

func (smokeUnlimitedBudgetRepo) GetByUserID(_ context.Context, _ string) (*domain.Budget, error) {
	return nil, io.EOF
}
func (smokeUnlimitedBudgetRepo) Upsert(_ context.Context, _ *domain.Budget) error   { return nil }
func (smokeUnlimitedBudgetRepo) UpdateSpent(_ context.Context, _ string, _ float64, _ int) error {
	return nil
}

type smokeEmptyPolicyRepo struct{}

func (smokeEmptyPolicyRepo) List(_ context.Context) ([]domain.PolicyRule, error) { return nil, nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func prometheusCounterSum(name string) float64 {
	mfs, _ := prometheus.DefaultGatherer.Gather()
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		var sum float64
		for _, m := range mf.GetMetric() {
			if c := m.GetCounter(); c != nil {
				sum += c.GetValue()
			}
		}
		return sum
	}
	return 0
}

func limitStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

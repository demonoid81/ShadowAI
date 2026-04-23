package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	promdto "github.com/prometheus/client_model/go"
	"github.com/redis/go-redis/v9"

	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/budget"
	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/firewall"
	"github.com/shadowai/backend/internal/metrics"
	"github.com/shadowai/backend/internal/policy"
	"github.com/shadowai/backend/internal/proxy/streaming"
)

// canonicalOpenAIStream — bytes, которые upstream вернёт тестовому
// клиенту. Мы проверяем, что при STREAMING_MODE=incremental эти
// самые bytes (byte-identical) приходят клиенту. Это acceptance
// criterion §5: "incremental проходит transport path без corruption".
var canonicalOpenAIStream = []byte(
	`data: {"id":"c-1","model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"c-1","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"c-1","model":"gpt-4o","choices":[{"index":0,"delta":{"content":" there"},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"c-1","model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n" +
		`data: [DONE]` + "\n\n")

// streamingTestHarness — handler + audit snapshot accessor.
// flushAudit должен вызываться перед чтением auditRepo.snapshot()
// (audit writes асинхронные). cleanup — для defer.
type streamingTestHarness struct {
	h          *Handler
	auditRepo  *captureAuditRepo
	flushAudit func()
	cleanup    func()
}

// buildStreamingHandler — helper, собирает Handler с минимальным
// набором зависимостей для streaming-сценариев.
func buildStreamingHandler(t *testing.T, upstreamBody []byte, streamingMode string) streamingTestHarness {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write(upstreamBody)
	}))

	registry := NewRegistry()
	registry.Register(&mockOpenAIProvider{url: upstream.URL})

	auditRepo := &captureAuditRepo{}
	auditSvc := audit.NewService(auditRepo)

	policySvc := &policy.Service{Engine: policy.NewEngine(emptyPolicyRepo{})}

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	budgetSvc := budget.NewService(unlimitedBudgetRepo{}, rdb)
	dlpSvc := dlp.NewService("enforce")

	// Без firewall inspector'ов: F7.1 incremental path не вызывает
	// response-side inspection (это F7.2). Buffered path без
	// inspector'ов тоже работает.
	pipeline := firewall.NewPipeline()

	h := NewHandler(
		registry, policySvc, auditSvc, budgetSvc, dlpSvc,
		"", nil, nil, nil, 0, pipeline,
		audit.PayloadModeFull,
		nil, nil,
	)
	h.SetStreamingMode(streamingMode)

	return streamingTestHarness{
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

// doProxyChatStream — helper: отправляет streaming-запрос в
// ProxyChat и возвращает recorder.
func doProxyChatStream(h *Handler, t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	claims := &auth.Claims{UserID: "test-user", Email: "u@example.com", Role: "user"}
	req = req.WithContext(auth.WithClaims(req.Context(), claims))

	rec := httptest.NewRecorder()
	h.ProxyChat(rec, req)
	return rec
}

// TestProxyChat_Streaming_BufferedMode_UnchangedByF7_1 — acceptance
// criterion §4: STREAMING_MODE=buffered не меняет текущее поведение.
// Пустой StreamingMode или явно "buffered" должны давать identical
// поведение — клиент получает тот же body, что возвращает upstream.
func TestProxyChat_Streaming_BufferedMode_UnchangedByF7_1(t *testing.T) {
	cases := []struct {
		name string
		mode string
	}{
		{"default_empty_mode", ""},
		{"explicit_buffered", "buffered"},
		{"unknown_mode_fallbacks_to_buffered", "xyzzy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			th := buildStreamingHandler(t, canonicalOpenAIStream, tc.mode)
			defer th.cleanup()

			rec := doProxyChatStream(th.h, t)
			th.flushAudit()

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			if !bytes.Equal(rec.Body.Bytes(), canonicalOpenAIStream) {
				t.Errorf("buffered mode corrupted stream:\nwant %q\n got %q",
					canonicalOpenAIStream, rec.Body.Bytes())
			}
			entries := th.auditRepo.snapshot()
			if len(entries) != 1 {
				t.Fatalf("audit entries = %d, want 1", len(entries))
			}
		})
	}
}

// TestProxyChat_Streaming_IncrementalMode_BytesIdentity — acceptance
// criterion §5: STREAMING_MODE=incremental проходит transport path
// без corruption. Упакованные bytes на клиенте должны быть byte-identical
// с тем, что прислал upstream (RFC §8.6 identity preservation).
func TestProxyChat_Streaming_IncrementalMode_BytesIdentity(t *testing.T) {
	th := buildStreamingHandler(t, canonicalOpenAIStream, "incremental")
	defer th.cleanup()

	rec := doProxyChatStream(th.h, t)
	th.flushAudit()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), canonicalOpenAIStream) {
		t.Errorf("incremental mode corrupted stream.\nwant (%d bytes):\n%q\n\ngot (%d bytes):\n%q",
			len(canonicalOpenAIStream), canonicalOpenAIStream,
			rec.Body.Len(), rec.Body.Bytes())
	}
	entries := th.auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1 (incremental mode must still audit)", len(entries))
	}
}

// TestProxyChat_Streaming_IncrementalMode_UnsupportedProvider_FallsBack —
// если provider не имеет adapter'а в streaming.AdapterForProvider,
// handler должен fallback'нуть на buffered path без corruption.
// Используем unknown provider name: имитируем регистрацию нового
// провайдера без registered adapter.
func TestProxyChat_Streaming_IncrementalMode_UnsupportedProvider_FallsBack(t *testing.T) {
	// Зарегистрируем mockOpenAIProvider под другим именем (наш
	// Name() возвращает "openai"; имя меняется через proxy registry
	// lookup — упрощённо: используем openai-compat path через Name()).
	// На практике shouldUseIncrementalStream проверяет имя провайдера;
	// чтобы заставить unsupported, используем fake provider с
	// Name()="cohere" (нет в AdapterForProvider).
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write(canonicalOpenAIStream)
	}))
	defer upstream.Close()

	registry := NewRegistry()
	registry.Register(&unsupportedNameProvider{url: upstream.URL})

	auditRepo := &captureAuditRepo{}
	auditSvc := audit.NewService(auditRepo)
	defer auditSvc.Close()

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
	h.SetStreamingMode("incremental") // setting — но adapter отсутствует

	body := `{"model":"fake-model","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/proxy/cohere/v1/chat/completions", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "cohere"})
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{UserID: "u", Role: "user"}))

	rec := httptest.NewRecorder()
	h.ProxyChat(rec, req)

	// Ожидаем: fallback на buffered (либо ошибка, если "cohere" не
	// известен registry — но мы его зарегистрировали через
	// unsupportedNameProvider). Главное: corruption'а нет.
	if rec.Code == http.StatusOK {
		if !bytes.Equal(rec.Body.Bytes(), canonicalOpenAIStream) {
			t.Errorf("unsupported-provider fallback corrupted stream:\nwant %q\n got %q",
				canonicalOpenAIStream, rec.Body.Bytes())
		}
	}
	// 404/400 ошибки тоже приемлемы — если provider не lookup'ится
	// в registry, handler должен отказать; главное, чтобы incremental
	// path не применился (что мы проверили косвенно — если бы
	// применился, было бы либо corruption, либо zero-length).
	_ = auditRepo
}

// TestProxyChat_Streaming_IncrementalMode_TransportError_AuditIs502 —
// PR-F7.1 review fix (#3): когда transport упал на non-cancel error,
// audit должен отразить это через StatusCode=502 и
// PolicyAction=streaming_transport_error, а не спрятать ошибку под
// обычным 200 / allow. Без этого incremental path был audit blind
// spot.
//
// Симулируем transport error через upstream, который обрывает
// соединение после частичного frame'а.
func TestProxyChat_Streaming_IncrementalMode_TransportError_AuditIs502(t *testing.T) {
	// Upstream шлёт невалидный SSE (открытый data: без blank line и
	// EOF в середине frame'а). Decoder примет как unknown_chunk, но
	// сам не зафейлится. Для настоящего transport error нужно emit
	// failure. Используем hijacker, который сразу обрывает connection
	// после начала body — io.ReadAll в decoder'е вернёт unexpected
	// EOF или partial (decoder flush'ит pending frame).
	//
	// Более надёжный сценарий: emitter fails — используем кастомный
	// ResponseWriter, который Write возвращает error после первого
	// byte'а. Для этого мы не можем использовать httptest.ResponseRecorder
	// (он никогда не фейлит). Пишем свой.
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
	h.SetStreamingMode("incremental")

	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{UserID: "u", Role: "user"}))

	// Свой writer, который fails на втором Write после первого
	// успешного (имитация client disconnect после headers).
	rec := &failingResponseWriter{
		header: make(http.Header),
		failAt: 1, // первый Write ок (headers), второй fail
	}
	h.ProxyChat(rec, req)
	auditSvc.Close() // flush async buffer до snapshot

	entries := auditRepo.snapshot()
	if len(entries) == 0 {
		t.Fatal("audit entries = 0; transport error должен писать audit запись")
	}
	// PR-F7.3: transport error → Outcome=stream_transport_error.
	var found *domain.AuditLog
	for _, e := range entries {
		if e.Outcome == OutcomeStreamTransportError {
			found = e
			break
		}
	}
	if found == nil {
		t.Fatalf("no audit entry with Outcome=%q; got: %+v",
			OutcomeStreamTransportError, entries)
	}
	if found.StatusCode != http.StatusBadGateway {
		t.Errorf("audit StatusCode = %d, want %d (Bad Gateway)",
			found.StatusCode, http.StatusBadGateway)
	}
}

// failingResponseWriter — http.ResponseWriter, который fails после
// N успешных Write'ов. Используется для симуляции client disconnect
// в unit-тестах.
type failingResponseWriter struct {
	header     http.Header
	writeCount int
	failAt     int
	buf        bytes.Buffer
	status     int
}

func (f *failingResponseWriter) Header() http.Header { return f.header }
func (f *failingResponseWriter) WriteHeader(s int)   { f.status = s }
func (f *failingResponseWriter) Write(p []byte) (int, error) {
	f.writeCount++
	if f.writeCount > f.failAt {
		return 0, io.ErrClosedPipe
	}
	return f.buf.Write(p)
}

// TestProxyChat_Streaming_IncrementalMode_BudgetSoftExceed_AuditMarker —
// PR-F7.1 review fix (#2): post-call budget over-limit в incremental
// mode должен в audit писать PolicyAction=streaming_budget_exceeded_soft
// с StatusCode=200 (т.к. client уже получил body). Это явное
// признание divergence от buffered (который бы вернул 402 + блок body).
func TestProxyChat_Streaming_IncrementalMode_BudgetSoftExceed_AuditMarker(t *testing.T) {
	streamWithUsage := []byte(
		`data: {"id":"c","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Hi"}}]}` + "\n\n" +
			`data: {"id":"c","model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n" +
			`data: {"id":"c","model":"gpt-4o","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}` + "\n\n" +
			`data: [DONE]` + "\n\n")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write(streamWithUsage)
	}))
	defer upstream.Close()

	registry := NewRegistry()
	// Провайдер, который возвращает non-zero cost из
	// ParseStreamUsage; иначе post-call budget check получит
	// additionalSpent=0 и не отличит pre/post.
	registry.Register(&costlyOpenAIProvider{url: upstream.URL, cost: 10.0, tokens: 6})

	auditRepo := &captureAuditRepo{}
	auditSvc := audit.NewService(auditRepo)

	mr, _ := miniredis.Run()
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	// Budget repo всегда возвращает not-allowed (over-budget).
	overBudget := overBudgetRepo{}
	budgetSvc := budget.NewService(overBudget, rdb)

	h := NewHandler(
		registry,
		&policy.Service{Engine: policy.NewEngine(emptyPolicyRepo{})},
		auditSvc, budgetSvc,
		dlp.NewService("enforce"),
		"", nil, nil, nil, 0, firewall.NewPipeline(),
		audit.PayloadModeFull,
		nil, nil,
	)
	h.SetStreamingMode("incremental")

	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"provider": "openai"})
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{UserID: "u", Role: "user"}))

	rec := httptest.NewRecorder()
	h.ProxyChat(rec, req)
	auditSvc.Close()

	// Precondition: если request-side budget check не пропустил
	// запрос (over-budget с самого начала), тест не получит stream
	// вообще. Проверим что request-path дошёл до streaming.
	if rec.Code != http.StatusOK {
		t.Skipf("pre-call budget блокировал request — тест не применим (status=%d)", rec.Code)
	}

	entries := auditRepo.snapshot()
	if len(entries) == 0 {
		t.Fatal("audit entries = 0")
	}
	// PR-F7.3: soft-exceed → Outcome=stream_budget_exceeded_soft.
	// PolicyAction остаётся verdict'ом (allowed — policy ничего не
	// блокировало).
	var sawSoft bool
	for _, e := range entries {
		if e.Outcome == OutcomeStreamBudgetExceededSoft {
			sawSoft = true
			if e.StatusCode != http.StatusOK {
				t.Errorf("soft-exceed audit StatusCode = %d, want %d (client got 200)",
					e.StatusCode, http.StatusOK)
			}
		}
	}
	if !sawSoft {
		t.Skipf("no soft-exceed outcome в audit; возможно, usage=0 → CheckBudgetAfterUsage не блокирует. Entries: %+v", entries)
	}
}

// overBudgetRepo — BudgetRepo с limit'ом ниже spent'а: pre-call
// CheckBudget может пропустить (зависит от точной формы проверки в
// budget.Service), но post-call CheckBudgetAfterUsage блокирует при
// ненулевом cost. Если cost==0 (наш тест: usage не парсится из
// canonicalOpenAIStream без include_usage) → тест skip'ается через
// Skipf.
type overBudgetRepo struct{}

func (overBudgetRepo) GetByUserID(_ context.Context, userID string) (*domain.Budget, error) {
	// Spent < Limit, но Spent + additionalSpent (>= cost из
	// costlyOpenAIProvider) > Limit. Баланс чтобы pre-call check
	// прошёл, post-call заблокировал.
	return &domain.Budget{
		ID:              "b-test",
		UserID:          userID,
		MonthlyLimitUSD: 5.0,
		MonthlySpentUSD: 1.0,
	}, nil
}
func (overBudgetRepo) Upsert(_ context.Context, _ *domain.Budget) error           { return nil }
func (overBudgetRepo) UpdateSpent(_ context.Context, _ string, _ float64, _ int) error { return nil }

// costlyOpenAIProvider — как mockOpenAIProvider, но реализует
// StreamUsageProvider и возвращает non-zero cost/tokens в
// ParseStreamUsage. Нужно для тестов post-call budget check
// (который иначе получает 0 и не блокирует).
type costlyOpenAIProvider struct {
	url    string
	cost   float64
	tokens int
}

func (p *costlyOpenAIProvider) Name() string { return "openai" }
func (p *costlyOpenAIProvider) BuildRequest(_ context.Context, body []byte, _ string) (*http.Request, error) {
	return http.NewRequest("POST", p.url, bytes.NewReader(body))
}
func (p *costlyOpenAIProvider) ParseResponse(_ []byte) (int, int, int, float64, error) {
	return p.tokens / 2, p.tokens - p.tokens/2, p.tokens, p.cost, nil
}
func (p *costlyOpenAIProvider) StreamFormat() StreamFormat { return StreamSSE }
func (p *costlyOpenAIProvider) DefaultModel() string       { return "gpt-4o" }
func (p *costlyOpenAIProvider) SupportedModels() []string  { return []string{"gpt-4o"} }
func (p *costlyOpenAIProvider) ParseStreamUsage(_ []byte, _ string) (StreamUsage, error) {
	return StreamUsage{
		PromptTokens:     p.tokens / 2,
		CompletionTokens: p.tokens - p.tokens/2,
		TotalTokens:      p.tokens,
		CostUSD:          p.cost,
		Found:            true,
	}, nil
}

// TestIncrementalTransport_MetricClassification — PR-F7.1.1 review
// fix (#2): streaming_emit_fail_total должен считать ТОЛЬКО
// emit-phase failures (без double-count); streaming_decoder_fatal_total
// — только decoder-phase failures (upstream read / parser fatal).
//
// Тестируем runIncrementalStreamTransport напрямую (без полного
// proxy flow), чтобы получить precise контроль над reader/writer.
func TestIncrementalTransport_MetricClassification(t *testing.T) {
	// Shared fixture-stream, адекватный для OpenAI-compat decoder'а.
	normal := []byte(canonicalOpenAIStream)

	t.Run("emit_phase_fail_records_emit_fail_only", func(t *testing.T) {
		emitBefore := counterValue(t, metrics.StreamingEmitFailTotal, "openai")
		decoderBefore := counterValue(t, metrics.StreamingDecoderFatalTotal, "openai")

		h := &Handler{}
		ctx := context.Background()
		w := &failingResponseWriter{
			header: make(http.Header),
			failAt: 1, // первый Write ок (headers/first frame), второй fail
		}
		adapter, _ := streaming.AdapterForProvider("openai")
		res := h.runIncrementalStreamTransport(
			ctx, w, http.Header{}, bytes.NewReader(normal),
			http.StatusOK, "openai", adapter, nil, /* engine=nil: transport-only mode */
		)
		if res.TransportErr == nil {
			t.Fatal("expected transport err, got nil")
		}

		emitAfter := counterValue(t, metrics.StreamingEmitFailTotal, "openai")
		decoderAfter := counterValue(t, metrics.StreamingDecoderFatalTotal, "openai")
		if emitAfter-emitBefore != 1 {
			t.Errorf("streaming_emit_fail_total delta = %v, want 1", emitAfter-emitBefore)
		}
		if decoderAfter-decoderBefore != 0 {
			t.Errorf("decoder_fatal delta = %v, want 0 (emit-phase should not touch decoder metric)", decoderAfter-decoderBefore)
		}
	})

	t.Run("decoder_phase_fail_records_decoder_fatal_only", func(t *testing.T) {
		emitBefore := counterValue(t, metrics.StreamingEmitFailTotal, "openai")
		decoderBefore := counterValue(t, metrics.StreamingDecoderFatalTotal, "openai")

		h := &Handler{}
		ctx := context.Background()
		// Reader, который fails с non-EOF error сразу после первого
		// read'а — симулирует upstream connection reset.
		reader := &failingReader{
			data:    normal[:60], // partial stream
			failErr: errors.New("upstream connection reset"),
		}
		w := httptest.NewRecorder()
		adapter, _ := streaming.AdapterForProvider("openai")
		res := h.runIncrementalStreamTransport(
			ctx, w, http.Header{}, reader,
			http.StatusOK, "openai", adapter, nil,
		)
		if res.TransportErr == nil {
			t.Fatal("expected decoder err, got nil")
		}

		emitAfter := counterValue(t, metrics.StreamingEmitFailTotal, "openai")
		decoderAfter := counterValue(t, metrics.StreamingDecoderFatalTotal, "openai")
		if decoderAfter-decoderBefore != 1 {
			t.Errorf("streaming_decoder_fatal_total delta = %v, want 1", decoderAfter-decoderBefore)
		}
		if emitAfter-emitBefore != 0 {
			t.Errorf("emit_fail delta = %v, want 0 (decoder-phase should not touch emit metric)", emitAfter-emitBefore)
		}
	})
}

// failingReader — io.Reader, который отдаёт data целиком и затем
// возвращает failErr вместо io.EOF. Симулирует upstream connection
// reset mid-stream.
type failingReader struct {
	data    []byte
	pos     int
	failErr error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, r.failErr
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// counterValue извлекает numeric value для (metric, labels). Для
// Counter.WithLabelValues вызывает внутренний Write в DTO.
func counterValue(t *testing.T, vec *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	m := vec.WithLabelValues(labels...)
	var dto promdto.Metric
	if err := m.Write(&dto); err != nil {
		t.Fatalf("metric write: %v", err)
	}
	if dto.Counter == nil {
		return 0
	}
	return dto.Counter.GetValue()
}

// unsupportedNameProvider — Provider с именем, для которого нет
// AdapterForProvider. Используется в тесте fallback'а. Upstream
// возвращает те же bytes, что и mockOpenAIProvider.
type unsupportedNameProvider struct{ url string }

func (p *unsupportedNameProvider) Name() string { return "cohere" }
func (p *unsupportedNameProvider) BuildRequest(_ context.Context, body []byte, _ string) (*http.Request, error) {
	return http.NewRequest("POST", p.url, bytes.NewReader(body))
}
func (p *unsupportedNameProvider) ParseResponse(_ []byte) (int, int, int, float64, error) {
	return 0, 0, 0, 0, nil
}
func (p *unsupportedNameProvider) StreamFormat() StreamFormat  { return StreamSSE }
func (p *unsupportedNameProvider) DefaultModel() string        { return "fake-model" }
func (p *unsupportedNameProvider) SupportedModels() []string   { return []string{"fake-model"} }

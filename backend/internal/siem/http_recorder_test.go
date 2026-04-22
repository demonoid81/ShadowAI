//go:build enterprise

package siem

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// capturedRequest — то, что SIEM-mock получает.
type capturedRequest struct {
	Headers http.Header
	Body    envelope
}

// mockSIEMServer возвращает httptest.Server + канал полученных
// requests + функцию для управления status-code.
func mockSIEMServer(t *testing.T, status int) (*httptest.Server, <-chan capturedRequest) {
	t.Helper()
	ch := make(chan capturedRequest, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env envelope
		_ = json.Unmarshal(body, &env)
		ch <- capturedRequest{Headers: r.Header.Clone(), Body: env}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

// TestHTTPRecorder_SendsExpectedPayload — базовая проверка, что
// envelope с правильным source/stream/event уходит на sink.
func TestHTTPRecorder_SendsExpectedPayload(t *testing.T) {
	srv, ch := mockSIEMServer(t, http.StatusOK)
	r := NewHTTPRecorder(srv.URL, "", 2*time.Second, false)
	actor := "u-admin"
	ev := Event{
		ActorUserID: &actor, Action: "read", Resource: "audit_logs",
		Path: "/api/audit/logs", Method: "GET",
		StatusCode: 200, Success: true,
		Metadata:  map[string]any{"filter": "model=gpt-4"},
		CreatedAt: "2026-04-22T12:00:00Z",
	}
	r.Record(context.Background(), ev)

	select {
	case req := <-ch:
		if req.Body.Source != "shadowai" {
			t.Errorf("source = %q, want shadowai", req.Body.Source)
		}
		if req.Body.Stream != "admin_event_logs" {
			t.Errorf("stream = %q", req.Body.Stream)
		}
		if req.Body.Event.Action != "read" || req.Body.Event.Resource != "audit_logs" {
			t.Errorf("event shape wrong: %+v", req.Body.Event)
		}
		if req.Headers.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", req.Headers.Get("Content-Type"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sink не получил request")
	}
}

// TestHTTPRecorder_SetsBearerToken — Authorization: Bearer ... header
// проставляется когда token задан.
func TestHTTPRecorder_SetsBearerToken(t *testing.T) {
	srv, ch := mockSIEMServer(t, http.StatusOK)
	r := NewHTTPRecorder(srv.URL, "secret-token-123", 2*time.Second, false)
	r.Record(context.Background(), Event{Action: "test", Resource: "x"})

	req := <-ch
	got := req.Headers.Get("Authorization")
	if got != "Bearer secret-token-123" {
		t.Errorf("Authorization = %q, want Bearer secret-token-123", got)
	}
}

// TestHTTPRecorder_NoBearerToken_NoAuthHeader — если token пустой,
// Authorization header НЕ должен проставляться.
func TestHTTPRecorder_NoBearerToken_NoAuthHeader(t *testing.T) {
	srv, ch := mockSIEMServer(t, http.StatusOK)
	r := NewHTTPRecorder(srv.URL, "", 2*time.Second, false)
	r.Record(context.Background(), Event{Action: "test", Resource: "x"})

	req := <-ch
	if auth := req.Headers.Get("Authorization"); auth != "" {
		t.Errorf("Authorization = %q, want empty (no token configured)", auth)
	}
}

// TestHTTPRecorder_EmptyEndpoint_NoOp — если endpoint пустой
// (ошибочная конфигурация, fallback), Record не должен делать
// сетевого вызова. Мы не можем это измерить напрямую, но можем
// проверить что вызов не паникует и не блокирует дольше миллисекунд.
func TestHTTPRecorder_EmptyEndpoint_NoOp(t *testing.T) {
	r := NewHTTPRecorder("", "", 2*time.Second, false)
	start := time.Now()
	r.Record(context.Background(), Event{Action: "test"})
	if time.Since(start) > 10*time.Millisecond {
		t.Errorf("no-op Record took %v (expected ~instant)", time.Since(start))
	}
}

// TestHTTPRecorder_500_DoesNotPanic — sink возвращает 500, Record
// не паникует и не блокирует caller.
func TestHTTPRecorder_500_DoesNotPanic(t *testing.T) {
	srv, _ := mockSIEMServer(t, http.StatusInternalServerError)
	r := NewHTTPRecorder(srv.URL, "", 2*time.Second, false)

	defer func() {
		if rec := recover(); rec != nil {
			t.Errorf("panic: %v", rec)
		}
	}()
	r.Record(context.Background(), Event{Action: "read", Resource: "x"})
}

// TestHTTPRecorder_Timeout_DoesNotBlock — sink висит дольше timeout.
// Record должен вернуться в рамках timeout+небольшой margin.
//
// Важно: blocker закрывается ПЕРЕД srv.Close(), иначе httptest
// ждёт активные connections в Close() → deadlock с hanging handler'ом.
func TestHTTPRecorder_Timeout_DoesNotBlock(t *testing.T) {
	blocker := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocker
	}))
	t.Cleanup(func() {
		close(blocker) // сначала освобождаем handler'ы,
		srv.Close()    // потом ждём завершения соединений.
	})

	r := NewHTTPRecorder(srv.URL, "", 100*time.Millisecond, false)
	start := time.Now()
	r.Record(context.Background(), Event{Action: "read", Resource: "x"})
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("Record took %v, want ~100ms", elapsed)
	}
}

// TestHTTPRecorder_PayloadNoExtraFields — privacy regression:
// envelope содержит ровно {source, stream, event}, и event — поля
// из siem.Event + Metadata-as-is. Никаких новых ключей в top-level.
func TestHTTPRecorder_PayloadNoExtraFields(t *testing.T) {
	var (
		rawBody []byte
		mu      sync.Mutex
		done    = make(chan struct{})
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
		body, _ := io.ReadAll(rq.Body)
		mu.Lock()
		rawBody = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		close(done)
	}))
	defer srv.Close()

	r := NewHTTPRecorder(srv.URL, "", 2*time.Second, false)
	r.Record(context.Background(), Event{
		Action:     "read",
		Resource:   "audit_logs",
		StatusCode: 200,
		Success:    true,
		CreatedAt:  "2026-04-22T12:00:00Z",
	})

	<-done
	mu.Lock()
	body := rawBody
	mu.Unlock()

	// Top-level — только source, stream, event.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	allowedTop := map[string]bool{"source": true, "stream": true, "event": true}
	for k := range top {
		if !allowedTop[k] {
			t.Errorf("unexpected top-level key %q в envelope", k)
		}
	}
}

// TestHTTPRecorder_NilReceiver_Safe — *HTTPRecorder=nil не паникует.
// Это крайний защитный уровень: никто не должен так вызывать, но
// если wire передаст nil — мы не ломаемся.
func TestHTTPRecorder_NilReceiver_Safe(t *testing.T) {
	var r *HTTPRecorder
	defer func() {
		if rec := recover(); rec != nil {
			t.Errorf("panic: %v", rec)
		}
	}()
	r.Record(context.Background(), Event{Action: "x"})
}

// TestSinkHost_ExtractsHostOnly — utility функция не leak'ает query
// params / user-info в error logs.
func TestSinkHost_ExtractsHostOnly(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://siem.example.com/ingest?token=secret", "siem.example.com"},
		{"https://user:pass@siem.example.com/api", "siem.example.com"},
		{"not-a-url", "<invalid>"},
		{"", "<invalid>"},
	}
	for _, c := range cases {
		got := sinkHost(c.in)
		// Для "not-a-url" Go url.Parse вернёт пустой host, который
		// у нас fallback'ится на "<invalid>". Проверяем это.
		if strings.Contains(got, "secret") || strings.Contains(got, "pass") {
			t.Errorf("sinkHost(%q) leak'нул secret/creds: %q", c.in, got)
		}
		if got != c.want {
			t.Errorf("sinkHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

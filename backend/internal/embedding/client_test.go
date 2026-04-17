package embedding

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const eps = 1e-6

func approxEq(a, b float64) bool { return math.Abs(a-b) < eps }

// TestNewClient_ValidatesConfig — NewClient должен проверить обязательные
// поля конфигурации до первого HTTP-вызова.
func TestNewClient_ValidatesConfig(t *testing.T) {
	cases := []struct {
		name   string
		cfg    Config
		wantOK bool
	}{
		{
			name:   "ok_ollama",
			cfg:    Config{Provider: "ollama", Endpoint: "http://localhost:11434", Model: "nomic-embed-text", Dimension: 768, Timeout: time.Second},
			wantOK: true,
		},
		{
			name: "missing_provider",
			cfg:  Config{Endpoint: "x", Model: "m", Dimension: 4, Timeout: time.Second},
		},
		{
			name: "unknown_provider",
			cfg:  Config{Provider: "claude", Endpoint: "x", Model: "m", Dimension: 4, Timeout: time.Second},
		},
		{
			name: "missing_endpoint",
			cfg:  Config{Provider: "ollama", Model: "m", Dimension: 4, Timeout: time.Second},
		},
		{
			name: "missing_model",
			cfg:  Config{Provider: "ollama", Endpoint: "x", Dimension: 4, Timeout: time.Second},
		},
		{
			name: "missing_dimension",
			cfg:  Config{Provider: "ollama", Endpoint: "x", Model: "m", Timeout: time.Second},
		},
		{
			name: "zero_timeout",
			cfg:  Config{Provider: "ollama", Endpoint: "x", Model: "m", Dimension: 4},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewClient(tc.cfg)
			if tc.wantOK && err != nil {
				t.Errorf("want ok, got err: %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Errorf("want error, got nil")
			}
		})
	}
}

// TestEmbed_Ollama_Normalizes — клиент к Ollama: отправляет POST
// /api/embeddings c body {model, prompt}, получает {embedding}, возвращает
// L2-нормализованный вектор (norm ≈ 1).
func TestEmbed_Ollama_Normalizes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/embeddings" {
			t.Errorf("path = %q, want /api/embeddings", r.URL.Path)
		}
		var body struct {
			Model  string `json:"model"`
			Prompt string `json:"prompt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Model != "nomic-embed-text" || body.Prompt != "hello" {
			t.Errorf("body = %+v", body)
		}
		// Отдаём ненормализованный [3, 4] — норма = 5.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"embedding":[3.0, 4.0]}`))
	}))
	defer srv.Close()

	c, err := NewClient(Config{
		Provider: "ollama", Endpoint: srv.URL, Model: "nomic-embed-text",
		Dimension: 2, Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	emb, err := c.Embed(context.Background(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if len(emb.Vector) != 2 {
		t.Fatalf("len = %d, want 2", len(emb.Vector))
	}
	// [3,4] / 5 = [0.6, 0.8]
	if !approxEq(emb.Vector[0], 0.6) || !approxEq(emb.Vector[1], 0.8) {
		t.Errorf("vector = %v, want [0.6, 0.8]", emb.Vector)
	}
	// L2-norm ≈ 1
	norm := math.Sqrt(emb.Vector[0]*emb.Vector[0] + emb.Vector[1]*emb.Vector[1])
	if !approxEq(norm, 1.0) {
		t.Errorf("norm = %f, want ~1.0 (client должен нормализовать)", norm)
	}
}

// TestEmbed_OpenAI_Format — клиент к OpenAI: path /v1/embeddings, header
// Authorization Bearer, тело {model,input}, response {data:[{embedding}]}.
func TestEmbed_OpenAI_Format(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("path = %q, want /v1/embeddings", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sk-test" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"embedding":[1.0, 0.0, 0.0]}]}`))
	}))
	defer srv.Close()

	c, err := NewClient(Config{
		Provider: "openai", Endpoint: srv.URL, Model: "text-embedding-3-small",
		APIKey: "sk-test", Dimension: 3, Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	emb, err := c.Embed(context.Background(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if len(emb.Vector) != 3 || !approxEq(emb.Vector[0], 1.0) {
		t.Errorf("vector = %v", emb.Vector)
	}
}

// TestEmbed_DimensionMismatch — если провайдер вернул другой dim, Embed
// обязан вернуть error. Это защита от тихого рассогласования corpus vs
// runtime (cosine между разными embedding spaces не имеет смысла).
func TestEmbed_DimensionMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"embedding":[1.0, 2.0, 3.0, 4.0]}`))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{
		Provider: "ollama", Endpoint: srv.URL, Model: "m",
		Dimension: 2, // expected 2, provider returns 4
		Timeout:   time.Second,
	})
	_, err := c.Embed(context.Background(), "x")
	if err == nil {
		t.Fatal("want dimension-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "dimension") {
		t.Errorf("error должен упомянуть dimension: %v", err)
	}
}

// TestEmbed_HTTP5xx_ErrorBubble — 5xx ответ должен возвращаться как error
// (не как zero-vector). Caller (inspector) сам решает fail-open.
func TestEmbed_HTTP5xx_ErrorBubble(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"oom"}`))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{
		Provider: "ollama", Endpoint: srv.URL, Model: "m",
		Dimension: 2, Timeout: time.Second,
	})
	_, err := c.Embed(context.Background(), "x")
	if err == nil {
		t.Error("want error on 5xx, got nil")
	}
}

// TestEmbed_Timeout — клиент уважает context deadline. Hang-handler >
// timeout → ошибка с признаком timeout'а, чтобы caller мог разделить
// инкремент timeout vs fail метрики.
func TestEmbed_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"embedding":[1.0]}`))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{
		Provider: "ollama", Endpoint: srv.URL, Model: "m",
		Dimension: 1, Timeout: 50 * time.Millisecond,
	})
	_, err := c.Embed(context.Background(), "x")
	if err == nil {
		t.Fatal("want timeout error")
	}
	if !IsTimeout(err) {
		t.Errorf("want IsTimeout(err), got: %v", err)
	}
}

// TestEmbed_ZeroVector_NoDivByZero — защита от деления на ноль при L2-
// нормализации: zero-вектор возвращается как есть (провайдер вернул
// degenerate response — поднимаем error, чтобы не портить corpus matching).
func TestEmbed_ZeroVector_NoDivByZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"embedding":[0.0, 0.0]}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{
		Provider: "ollama", Endpoint: srv.URL, Model: "m",
		Dimension: 2, Timeout: time.Second,
	})
	_, err := c.Embed(context.Background(), "x")
	if err == nil {
		t.Error("zero-vector из провайдера — это degenerate, должна быть error")
	}
}

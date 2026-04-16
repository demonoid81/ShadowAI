package firewall

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shadowai/backend/internal/metrics"
)

// TestJudge_MetricsOnSuccess — счётчик requests_total инкрементируется
// на каждый успешный вызов + latency histogram наблюдается.
func TestJudge_MetricsOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"is_threat\":true,\"confidence\":0.9,\"reason\":\"test\"}"}}]}`))
	}))
	defer srv.Close()

	j := NewJudge(JudgeConfig{
		Provider: "openai",
		Model:    "gpt-4",
		Endpoint: srv.URL,
		APIKey:   "test",
		Timeout:  2 * time.Second,
		Enabled:  true,
	})

	// Baseline
	before := testutil_counterValue(t, metrics.JudgeRequestsTotal.WithLabelValues("openai", "prompt_injection"))

	result, err := j.Evaluate(context.Background(), "evil", "prompt_injection")
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsThreat {
		t.Error("ожидался IsThreat=true")
	}

	after := testutil_counterValue(t, metrics.JudgeRequestsTotal.WithLabelValues("openai", "prompt_injection"))
	if after-before != 1 {
		t.Errorf("JudgeRequestsTotal: delta = %g, want 1", after-before)
	}

	// latency histogram sample добавлен
	samples := testutil_histogramSampleCount(t, metrics.JudgeLatencySeconds.WithLabelValues("openai", "prompt_injection"))
	if samples == 0 {
		t.Errorf("JudgeLatencySeconds: нет samples после успешного вызова")
	}
}

// TestJudge_MetricsOnMalformedContent — provider возвращает 200 OK, но
// body не парсится через extractContent. Должны инкрементироваться
// malformed + fallback, НЕ timeout, НЕ generic fail.
func TestJudge_MetricsOnMalformedContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Valid JSON, но без expected schema (нет choices[0].message.content).
		_, _ = w.Write([]byte(`{"unexpected":"shape"}`))
	}))
	defer srv.Close()

	j := NewJudge(JudgeConfig{
		Provider: "openai",
		Model:    "gpt-4",
		Endpoint: srv.URL,
		APIKey:   "test",
		Timeout:  2 * time.Second,
		Enabled:  true,
	})

	malformedBefore := testutil_counterValue(t, metrics.JudgeMalformedTotal.WithLabelValues("openai", "jailbreak"))
	fallbackBefore := testutil_counterValue(t, metrics.JudgeFallbackTotal.WithLabelValues("openai", "jailbreak"))
	timeoutBefore := testutil_counterValue(t, metrics.JudgeTimeoutTotal.WithLabelValues("openai", "jailbreak"))

	result, err := j.Evaluate(context.Background(), "evil", "jailbreak")
	if err != nil {
		t.Fatalf("malformed должен возвращать soft-allow, не error: %v", err)
	}
	if result.IsThreat {
		t.Error("fallback path должен возвращать IsThreat=false")
	}
	if result.Reason != "malformed response" {
		t.Errorf("Reason = %q, want 'malformed response' (видимое решение fallback)", result.Reason)
	}

	malformedAfter := testutil_counterValue(t, metrics.JudgeMalformedTotal.WithLabelValues("openai", "jailbreak"))
	fallbackAfter := testutil_counterValue(t, metrics.JudgeFallbackTotal.WithLabelValues("openai", "jailbreak"))
	timeoutAfter := testutil_counterValue(t, metrics.JudgeTimeoutTotal.WithLabelValues("openai", "jailbreak"))

	if malformedAfter-malformedBefore != 1 {
		t.Errorf("JudgeMalformedTotal: delta = %g, want 1", malformedAfter-malformedBefore)
	}
	if fallbackAfter-fallbackBefore != 1 {
		t.Errorf("JudgeFallbackTotal: delta = %g, want 1 (видимое security решение)", fallbackAfter-fallbackBefore)
	}
	if timeoutAfter-timeoutBefore != 0 {
		t.Errorf("JudgeTimeoutTotal инкрементировался (%g), хотя это НЕ timeout", timeoutAfter-timeoutBefore)
	}
}

// TestJudge_MetricsOnMalformedJSONPayload — provider вернул content,
// но content не валидный JSON судьиной схемы. Второй malformed path
// через parseJudgeResponse.
func TestJudge_MetricsOnMalformedJSONPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Content есть, но он не JSON.
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"I think this is fine"}}]}`))
	}))
	defer srv.Close()

	j := NewJudge(JudgeConfig{
		Provider: "openai",
		Model:    "gpt-4",
		Endpoint: srv.URL,
		APIKey:   "test",
		Timeout:  2 * time.Second,
		Enabled:  true,
	})

	before := testutil_counterValue(t, metrics.JudgeMalformedTotal.WithLabelValues("openai", "content_moderation"))

	result, err := j.Evaluate(context.Background(), "test", "content_moderation")
	if err != nil {
		t.Fatalf("malformed payload должен возвращать soft-allow: %v", err)
	}
	if result.IsThreat {
		t.Error("malformed payload path → IsThreat=false")
	}

	after := testutil_counterValue(t, metrics.JudgeMalformedTotal.WithLabelValues("openai", "content_moderation"))
	if after-before != 1 {
		t.Errorf("JudgeMalformedTotal: delta = %g, want 1 (parseJudgeResponse malformed path)", after-before)
	}
}

// TestJudge_MetricsOnTimeout — судья не отвечает в отведённое время.
// Должен быть timeout counter + ошибка возвращена наружу.
func TestJudge_MetricsOnTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	j := NewJudge(JudgeConfig{
		Provider: "ollama",
		Model:    "llama",
		Endpoint: srv.URL,
		Timeout:  50 * time.Millisecond, // короче server-sleep
		Enabled:  true,
	})

	timeoutBefore := testutil_counterValue(t, metrics.JudgeTimeoutTotal.WithLabelValues("ollama", "prompt_injection"))
	failBefore := testutil_counterValue(t, metrics.JudgeFailTotal.WithLabelValues("ollama", "prompt_injection"))

	_, err := j.Evaluate(context.Background(), "test", "prompt_injection")
	if err == nil {
		t.Fatal("ожидался error при timeout")
	}

	timeoutAfter := testutil_counterValue(t, metrics.JudgeTimeoutTotal.WithLabelValues("ollama", "prompt_injection"))
	failAfter := testutil_counterValue(t, metrics.JudgeFailTotal.WithLabelValues("ollama", "prompt_injection"))

	if timeoutAfter-timeoutBefore != 1 {
		t.Errorf("JudgeTimeoutTotal: delta = %g, want 1", timeoutAfter-timeoutBefore)
	}
	if failAfter-failBefore != 0 {
		t.Errorf("JudgeFailTotal должен быть БЕЗ инкремента при timeout (separate alert path), got delta=%g",
			failAfter-failBefore)
	}
}

// TestJudge_MetricsOnHTTPError — provider вернул 5xx. Generic fail counter.
func TestJudge_MetricsOnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal", http.StatusInternalServerError)
	}))
	defer srv.Close()

	j := NewJudge(JudgeConfig{
		Provider: "openai",
		Model:    "gpt-4",
		Endpoint: srv.URL,
		APIKey:   "key",
		Timeout:  2 * time.Second,
		Enabled:  true,
	})

	before := testutil_counterValue(t, metrics.JudgeFailTotal.WithLabelValues("openai", "jailbreak"))

	_, err := j.Evaluate(context.Background(), "test", "jailbreak")
	if err == nil {
		t.Fatal("ожидался error для 500 от провайдера")
	}
	if !strings.Contains(err.Error(), "unexpected status") {
		t.Errorf("unexpected error message: %v", err)
	}

	after := testutil_counterValue(t, metrics.JudgeFailTotal.WithLabelValues("openai", "jailbreak"))
	if after-before != 1 {
		t.Errorf("JudgeFailTotal: delta = %g, want 1", after-before)
	}
}

// TestJudge_DisabledNoMetrics — disabled judge НЕ инкрементирует
// requests_total (denominator должен отражать только real attempts).
func TestJudge_DisabledNoMetrics(t *testing.T) {
	j := NewJudge(JudgeConfig{Enabled: false})

	before := testutil_counterValue(t, metrics.JudgeRequestsTotal.WithLabelValues("", "test"))

	result, err := j.Evaluate(context.Background(), "text", "test")
	if err != nil {
		t.Fatal(err)
	}
	if result.IsThreat {
		t.Error("disabled → IsThreat=false")
	}

	after := testutil_counterValue(t, metrics.JudgeRequestsTotal.WithLabelValues("", "test"))
	if after != before {
		t.Errorf("disabled judge НЕ должен инкрементировать counter, got delta=%g", after-before)
	}
}

// TestJudge_ConfigSanitizesAPIKey — status API не должен показывать APIKey.
func TestJudge_ConfigSanitizesAPIKey(t *testing.T) {
	j := NewJudge(JudgeConfig{
		Provider: "openai",
		APIKey:   "secret-key-do-not-leak",
		Timeout:  time.Second,
		Enabled:  true,
	})
	got := j.Config()
	if got.APIKey != "" {
		t.Errorf("Config() вернул APIKey=%q — утечка через status API", got.APIKey)
	}
	if got.Provider != "openai" {
		t.Errorf("Config() должен сохранять non-secret fields, got Provider=%q", got.Provider)
	}
}

// TestJudge_ConfigNilSafe — Config() на nil judge безопасен.
func TestJudge_ConfigNilSafe(t *testing.T) {
	var j *Judge
	got := j.Config()
	if got.Enabled {
		t.Error("nil judge должен возвращать zero config")
	}
}

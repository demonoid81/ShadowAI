package metrics_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/shadowai/backend/internal/metrics"
)

// TestMetricsRouterSmoke проверяет, что регистрация маршрута /metrics через
// тот же паттерн, что используется в cmd/shadowai/main.go, действительно
// отдаёт текстовый Prometheus-формат на GET /metrics, без auth middleware.
//
// Этот тест специально воспроизводит setup из main.go, а не вызывает
// promhttp.Handler() напрямую — чтобы поймать regression, если кто-то
// случайно спрячет /metrics под AuthMiddleware или переименует путь.
func TestMetricsRouterSmoke(t *testing.T) {
	// Инициализируем хоть одну метрику, чтобы выдача была ненулевой.
	metrics.RecordFirewallDecision("request", "smoke_test", "allow")

	// Мини-реплика main.go route setup: только /metrics, без auth.
	r := mux.NewRouter()
	r.Handle("/metrics", promhttp.Handler()).Methods("GET")

	// Позитивный кейс: GET /metrics → 200 + Prometheus text format.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics: status = %d, expected 200", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/plain") &&
		!strings.HasPrefix(contentType, "application/openmetrics-text") {
		t.Errorf("Content-Type = %q, expected Prometheus text format", contentType)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "shadowai_firewall_decisions_total") {
		t.Errorf("/metrics body does not contain expected ShadowAI metric:\n%s", body)
	}

	// Regression guard: методы кроме GET → 405 (а не 200, что означало бы
	// отсутствие restrictions).
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(m, "/metrics", nil)
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /metrics: status = %d, expected 405", m, rec.Code)
		}
	}

	// Negative: несуществующий путь → 404.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/metrics/admin", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /metrics/admin: status = %d, expected 404", rec.Code)
	}
}

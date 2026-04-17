package metrics_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/metrics"
)

// TestMetricsRouterSmoke проверяет РЕАЛЬНЫЙ wiring маршрута /metrics:
// main.go вызывает metrics.RegisterRoute(r), и этот тест вызывает ТУ ЖЕ
// функцию. Это гарантирует, что regression-guard сработает при:
//   - rename пути в RegisterRoute
//   - случайном заворачивании endpoint'а в AuthMiddleware (Prometheus ломается)
//   - изменении accepted methods или Content-Type handler'а
func TestMetricsRouterSmoke(t *testing.T) {
	// Инициализируем хоть одну метрику, чтобы выдача была ненулевой.
	metrics.RecordFirewallDecision("request", "smoke_test", "allow", "enforce")

	// Используем production-функцию регистрации маршрута.
	r := mux.NewRouter()
	metrics.RegisterRoute(r)

	// Path-константа тоже используется из production-источника, а не
	// захардкожена в тесте — чтобы случайный rename главного пути ломал
	// именно этот тест, а не сам scrape config.
	path := metrics.MetricsPath

	// Позитивный кейс: GET /metrics → 200 + Prometheus text format.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, expected 200", path, rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/plain") &&
		!strings.HasPrefix(contentType, "application/openmetrics-text") {
		t.Errorf("Content-Type = %q, expected Prometheus text format", contentType)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "shadowai_firewall_decisions_total") {
		t.Errorf("%s body does not contain expected ShadowAI metric:\n%s", path, body)
	}

	// Regression guard: методы кроме GET → 405 (а не 200, что означало бы
	// отсутствие restrictions).
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(m, path, nil)
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status = %d, expected 405", m, path, rec.Code)
		}
	}

	// Negative: несуществующий путь → 404.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, path+"/admin", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET %s/admin: status = %d, expected 404", path, rec.Code)
	}
}

// TestMetricsPath — guard-тест: путь /metrics является контрактом со
// scrape-инфраструктурой. Изменение этого пути должно быть осознанным
// решением (требуется обновление всех prometheus.yml). Если вы
// намеренно меняете путь — обновите эту константу и этот тест.
func TestMetricsPath(t *testing.T) {
	if metrics.MetricsPath != "/metrics" {
		t.Errorf("MetricsPath = %q, expected /metrics (scrape contract changed?)", metrics.MetricsPath)
	}
}

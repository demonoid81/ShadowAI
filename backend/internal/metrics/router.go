package metrics

import (
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsPath — путь, на котором экспортируется Prometheus telemetry.
// Константа, чтобы main.go и тесты ссылались на один источник истины
// и один случайный rename не приводил к silent breakage scrape-конфига.
const MetricsPath = "/metrics"

// RegisterRoute регистрирует /metrics на переданном router'е.
//
// ВАЖНО: маршрут НЕ оборачивается в AuthMiddleware — Prometheus-scrapers
// не авторизуются JWT. Ограничения должны применяться на уровне
// infrastructure (internal-only network, ingress auth, IP-allowlist).
// См. README секцию "Observability (Prometheus)".
//
// Этот helper вызывается из cmd/shadowai/main.go и из тестов —
// тесты проверяют РЕАЛЬНЫЙ wiring, а не свою копию setup-кода.
func RegisterRoute(r *mux.Router) {
	r.Handle(MetricsPath, promhttp.Handler()).Methods("GET")
}

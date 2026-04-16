package firewall

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/client_golang/prometheus"
)

// testutil_counterValue читает текущее значение Counter через
// prometheus collector Write. Используется для delta-проверок в тестах.
func testutil_counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("counter.Write: %v", err)
	}
	if m.Counter == nil {
		return 0
	}
	return m.Counter.GetValue()
}

// testutil_histogramSampleCount возвращает количество observed samples
// для Histogram. Используется когда важен факт наблюдения, не значение.
func testutil_histogramSampleCount(t *testing.T, h prometheus.Observer) uint64 {
	t.Helper()
	// Observer не экспортирует Write напрямую; используем type assertion
	// до Histogram (что даст доступ к Write).
	hist, ok := h.(prometheus.Histogram)
	if !ok {
		t.Fatalf("testutil_histogramSampleCount: expected prometheus.Histogram, got %T", h)
	}
	var m dto.Metric
	if err := hist.Write(&m); err != nil {
		t.Fatalf("histogram.Write: %v", err)
	}
	if m.Histogram == nil {
		return 0
	}
	return m.Histogram.GetSampleCount()
}

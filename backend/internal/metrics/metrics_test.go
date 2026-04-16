package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// TestMetricsEndpoint проверяет, что все объявленные метрики экспортируются
// через promhttp handler и отвечают в Prometheus text format.
func TestMetricsEndpoint(t *testing.T) {
	// Инициируем метрики ненулевыми значениями чтобы они появились в выдаче
	AuditQueueDepth.Set(42)
	AuditDroppedTotal.Inc()
	AuditInsertedTotal.Add(3)
	AuditFailedTotal.Inc()
	RecordFirewallDecision("request", "test_inspector", "flag")
	RecordBudgetBlock(true)
	RecordBudgetBlock(false)
	RecordStreamUsageParseFail("openai")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	promhttp.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, expected 200", rec.Code)
	}

	body := rec.Body.String()

	// Все метрики должны присутствовать в выдаче
	expected := []string{
		"shadowai_audit_queue_depth",
		"shadowai_audit_dropped_total",
		"shadowai_audit_inserted_total",
		"shadowai_audit_failed_total",
		"shadowai_firewall_decisions_total",
		"shadowai_proxy_budget_blocks_total",
		"shadowai_stream_usage_parse_fail_total",
	}
	for _, name := range expected {
		if !strings.Contains(body, name) {
			t.Errorf("metric %q missing from /metrics output", name)
		}
	}

	// Проверим, что labels работают
	expectedLabels := []string{
		`phase="request"`,
		`inspector="test_inspector"`,
		`action="flag"`,
		`streaming="true"`,
		`streaming="false"`,
		`provider="openai"`,
	}
	for _, label := range expectedLabels {
		if !strings.Contains(body, label) {
			t.Errorf("expected label %q not found in output", label)
		}
	}
}

func TestRecordBudgetBlock(t *testing.T) {
	RecordBudgetBlock(true)
	RecordBudgetBlock(false)
	// Счётчики накапливаются между тестами, конкретные значения не проверяем,
	// только факт, что вызов не падает.
}

func TestRecordAuditQueue(t *testing.T) {
	RecordAuditQueue(0)
	RecordAuditQueue(100)
	RecordAuditQueue(1000)
}

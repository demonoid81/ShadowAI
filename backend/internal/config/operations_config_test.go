package config

import (
	"testing"
	"time"
)

func TestLoad_OperationsPrometheusConfig(t *testing.T) {
	t.Setenv("OPERATIONS_PROMETHEUS_URL", "http://prometheus.monitoring.svc:9090")
	t.Setenv("OPERATIONS_PROMETHEUS_TIMEOUT", "7s")
	t.Setenv("OPERATIONS_EVIDENCE_EXPORT_QUERY", "export_query")
	t.Setenv("OPERATIONS_EVIDENCE_AUDIT_REPORT_QUERY", "audit_query")
	t.Setenv("OPERATIONS_PROMETHEUS_ALERTS_QUERY", "alerts_query")

	cfg := Load()

	if cfg.OperationsPrometheusURL != "http://prometheus.monitoring.svc:9090" {
		t.Fatalf("OperationsPrometheusURL = %q", cfg.OperationsPrometheusURL)
	}
	if cfg.OperationsPrometheusTimeout != 7*time.Second {
		t.Fatalf("OperationsPrometheusTimeout = %s, want 7s", cfg.OperationsPrometheusTimeout)
	}
	if cfg.OperationsEvidenceExportQuery != "export_query" {
		t.Fatalf("OperationsEvidenceExportQuery = %q", cfg.OperationsEvidenceExportQuery)
	}
	if cfg.OperationsEvidenceAuditReportQuery != "audit_query" {
		t.Fatalf("OperationsEvidenceAuditReportQuery = %q", cfg.OperationsEvidenceAuditReportQuery)
	}
	if cfg.OperationsPrometheusAlertsQuery != "alerts_query" {
		t.Fatalf("OperationsPrometheusAlertsQuery = %q", cfg.OperationsPrometheusAlertsQuery)
	}
}

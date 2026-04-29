package operations

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPrometheusClient_QueryValue_VectorSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			t.Fatalf("path = %s, want /api/v1/query", r.URL.Path)
		}
		if got := r.URL.Query().Get("query"); got != "sum(up)" {
			t.Fatalf("query = %q, want sum(up)", got)
		}
		writePrometheusResponse(t, w, map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "vector",
				"result": []any{
					map[string]any{"metric": map[string]string{}, "value": []any{float64(1), "0"}},
					map[string]any{"metric": map[string]string{}, "value": []any{float64(1), "2"}},
				},
			},
		})
	}))
	defer srv.Close()

	client, err := NewPrometheusClient(srv.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	value, found, err := client.QueryValue(context.Background(), "sum(up)")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("found = false, want true")
	}
	if value != 2 {
		t.Fatalf("value = %v, want max vector value 2", value)
	}
}

func TestPrometheusClient_QueryValue_ScalarSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writePrometheusResponse(t, w, map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "scalar",
				"result":     []any{float64(1), "3"},
			},
		})
	}))
	defer srv.Close()

	client, err := NewPrometheusClient(srv.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	value, found, err := client.QueryValue(context.Background(), "active_alerts")
	if err != nil {
		t.Fatal(err)
	}
	if !found || value != 3 {
		t.Fatalf("value/found = %v/%v, want 3/true", value, found)
	}
}

func TestPrometheusClient_QueryValue_EmptyVector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writePrometheusResponse(t, w, map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "vector",
				"result":     []any{},
			},
		})
	}))
	defer srv.Close()

	client, err := NewPrometheusClient(srv.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, found, err := client.QueryValue(context.Background(), "missing")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("found = true, want false")
	}
}

func TestPrometheusClient_QueryValue_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client, err := NewPrometheusClient(srv.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.QueryValue(context.Background(), "x"); err == nil {
		t.Fatal("err = nil, want HTTP error")
	}
}

func TestPrometheusSignals_MapsConfiguredQueries(t *testing.T) {
	q := fakePrometheusQuerier{
		values: map[string]float64{
			"export": 0,
			"audit":  1,
			"alerts": 2,
		},
	}
	cfg := RuntimeConfig{
		OperationsEvidenceExportQuery:      "export",
		OperationsEvidenceAuditReportQuery: "audit",
		OperationsPrometheusAlertsQuery:    "alerts",
	}

	signals := PrometheusSignals(context.Background(), cfg, q)

	if got := findSignalInSlice(t, signals, "evidence_export_cronjob"); got.Status != StatusOK {
		t.Fatalf("export status = %s, want ok", got.Status)
	}
	if got := findSignalInSlice(t, signals, "evidence_audit_report_cronjob"); got.Status != StatusError {
		t.Fatalf("audit status = %s, want error", got.Status)
	}
	if got := findSignalInSlice(t, signals, "prometheus_alerts"); got.Status != StatusWarn {
		t.Fatalf("alerts status = %s, want warn", got.Status)
	}
}

func TestBuildSnapshot_PrometheusSignalsOverrideUnknowns(t *testing.T) {
	snap := BuildSnapshot(
		RuntimeConfig{AuditRetentionDays: 30},
		DependencyStatus{DBOK: true, RedisOK: true},
		time.Now(),
		Signal{Key: "prometheus_alerts", Status: StatusOK, Source: "prometheus", Message: "ok"},
	)

	if got := findSignal(t, snap, "prometheus_alerts"); got.Status != StatusOK {
		t.Fatalf("prometheus_alerts status = %s, want ok", got.Status)
	}
}

func writePrometheusResponse(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatal(err)
	}
}

type fakePrometheusQuerier struct {
	values map[string]float64
	errs   map[string]error
	empty  map[string]bool
}

func (f fakePrometheusQuerier) QueryValue(_ context.Context, query string) (float64, bool, error) {
	if f.errs != nil && f.errs[query] != nil {
		return 0, false, f.errs[query]
	}
	if f.empty != nil && f.empty[query] {
		return 0, false, nil
	}
	value, ok := f.values[query]
	return value, ok, nil
}

func findSignalInSlice(t *testing.T, signals []Signal, key string) Signal {
	t.Helper()
	for _, signal := range signals {
		if signal.Key == key {
			return signal
		}
	}
	t.Fatalf("signal %q not found", key)
	return Signal{}
}

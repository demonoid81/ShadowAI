package operations

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

	signals := PrometheusSignals(context.Background(), cfg, q, time.Unix(100, 0).UTC())

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

func TestPrometheusSignals_FreshLastSuccessAddsDetails(t *testing.T) {
	now := time.Unix(200_000, 0).UTC()
	q := fakePrometheusQuerier{
		values: map[string]float64{
			"export":      0,
			"export_last": float64(now.Add(-2 * time.Hour).Unix()),
		},
	}
	cfg := RuntimeConfig{
		OperationsEvidenceExportQuery:            "export",
		OperationsEvidenceExportLastSuccessQuery: "export_last",
		OperationsEvidenceExportStaleAfter:       26 * time.Hour,
	}

	signals := PrometheusSignals(context.Background(), cfg, q, now)
	got := findSignalInSlice(t, signals, "evidence_export_cronjob")

	if got.Status != StatusOK {
		t.Fatalf("status = %s, want ok", got.Status)
	}
	if got.Details["last_success_at"] != now.Add(-2*time.Hour).UTC().Format(time.RFC3339) {
		t.Fatalf("last_success_at = %#v", got.Details["last_success_at"])
	}
	if got.Details["age_seconds"] != float64(7200) {
		t.Fatalf("age_seconds = %#v, want 7200", got.Details["age_seconds"])
	}
	if got.Details["stale_after_seconds"] != float64(93600) {
		t.Fatalf("stale_after_seconds = %#v, want 93600", got.Details["stale_after_seconds"])
	}
}

func TestPrometheusSignals_StaleLastSuccessWarns(t *testing.T) {
	now := time.Unix(200_000, 0).UTC()
	q := fakePrometheusQuerier{
		values: map[string]float64{
			"export":      0,
			"export_last": float64(now.Add(-30 * time.Hour).Unix()),
		},
	}
	cfg := RuntimeConfig{
		OperationsEvidenceExportQuery:            "export",
		OperationsEvidenceExportLastSuccessQuery: "export_last",
		OperationsEvidenceExportStaleAfter:       26 * time.Hour,
	}

	signals := PrometheusSignals(context.Background(), cfg, q, now)
	got := findSignalInSlice(t, signals, "evidence_export_cronjob")

	if got.Status != StatusWarn {
		t.Fatalf("status = %s, want warn", got.Status)
	}
}

func TestPrometheusSignals_CountViolationWinsOverFreshLastSuccess(t *testing.T) {
	now := time.Unix(200_000, 0).UTC()
	q := fakePrometheusQuerier{
		values: map[string]float64{
			"export":      1,
			"export_last": float64(now.Add(-time.Hour).Unix()),
		},
	}
	cfg := RuntimeConfig{
		OperationsEvidenceExportQuery:            "export",
		OperationsEvidenceExportLastSuccessQuery: "export_last",
		OperationsEvidenceExportStaleAfter:       26 * time.Hour,
	}

	signals := PrometheusSignals(context.Background(), cfg, q, now)
	got := findSignalInSlice(t, signals, "evidence_export_cronjob")

	if got.Status != StatusError {
		t.Fatalf("status = %s, want error", got.Status)
	}
}

func TestPrometheusSignals_EmptyLastSuccessUnknown(t *testing.T) {
	now := time.Unix(200_000, 0).UTC()
	q := fakePrometheusQuerier{
		values: map[string]float64{"export": 0},
		empty:  map[string]bool{"export_last": true},
	}
	cfg := RuntimeConfig{
		OperationsEvidenceExportQuery:            "export",
		OperationsEvidenceExportLastSuccessQuery: "export_last",
		OperationsEvidenceExportStaleAfter:       26 * time.Hour,
	}

	signals := PrometheusSignals(context.Background(), cfg, q, now)
	got := findSignalInSlice(t, signals, "evidence_export_cronjob")

	if got.Status != StatusUnknown {
		t.Fatalf("status = %s, want unknown", got.Status)
	}
	if got.Details["last_success_configured"] != true {
		t.Fatalf("last_success_configured = %#v, want true", got.Details["last_success_configured"])
	}
}

func TestPrometheusSignals_LastSuccessQueryErrorIsError(t *testing.T) {
	now := time.Unix(200_000, 0).UTC()
	q := fakePrometheusQuerier{
		values: map[string]float64{"export": 0},
		errs:   map[string]error{"export_last": errors.New("prometheus down")},
	}
	cfg := RuntimeConfig{
		OperationsEvidenceExportQuery:            "export",
		OperationsEvidenceExportLastSuccessQuery: "export_last",
		OperationsEvidenceExportStaleAfter:       26 * time.Hour,
	}

	signals := PrometheusSignals(context.Background(), cfg, q, now)
	got := findSignalInSlice(t, signals, "evidence_export_cronjob")

	if got.Status != StatusError {
		t.Fatalf("status = %s, want error", got.Status)
	}
}

func TestPrometheusSignals_DoesNotExposeRawQueries(t *testing.T) {
	now := time.Unix(200_000, 0).UTC()
	q := fakePrometheusQuerier{
		values: map[string]float64{
			"secret_count_query": 0,
			"secret_last_query":  float64(now.Add(-time.Hour).Unix()),
		},
	}
	cfg := RuntimeConfig{
		OperationsEvidenceExportQuery:            "secret_count_query",
		OperationsEvidenceExportLastSuccessQuery: "secret_last_query",
		OperationsEvidenceExportStaleAfter:       26 * time.Hour,
	}

	signals := PrometheusSignals(context.Background(), cfg, q, now)
	body, err := json.Marshal(signals)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret_count_query", "secret_last_query"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("response exposed raw query %q: %s", forbidden, string(body))
		}
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

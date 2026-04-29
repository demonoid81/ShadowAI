package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type PrometheusQuerier interface {
	QueryValue(ctx context.Context, query string) (float64, bool, error)
}

type PrometheusClient struct {
	baseURL *url.URL
	client  *http.Client
}

func NewPrometheusClient(rawURL string, timeout time.Duration) (PrometheusQuerier, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse operations prometheus url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("operations prometheus url must use http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("operations prometheus url must include host")
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &PrometheusClient{
		baseURL: parsed,
		client:  &http.Client{Timeout: timeout},
	}, nil
}

func (c *PrometheusClient) QueryValue(ctx context.Context, query string) (float64, bool, error) {
	if c == nil {
		return 0, false, nil
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return 0, false, nil
	}
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/query"
	q := endpoint.Query()
	q.Set("query", query)
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return 0, false, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, false, fmt.Errorf("prometheus query returned HTTP %d", resp.StatusCode)
	}

	var decoded prometheusQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return 0, false, err
	}
	if decoded.Status != "success" {
		if decoded.Error != "" {
			return 0, false, errors.New(decoded.Error)
		}
		return 0, false, fmt.Errorf("prometheus query status %q", decoded.Status)
	}
	return decoded.Value()
}

func PrometheusSignals(ctx context.Context, cfg RuntimeConfig, q PrometheusQuerier) []Signal {
	if q == nil {
		return nil
	}
	return []Signal{
		prometheusViolationSignal(ctx, q, "evidence_export_cronjob", cfg.OperationsEvidenceExportQuery, StatusError),
		prometheusViolationSignal(ctx, q, "evidence_audit_report_cronjob", cfg.OperationsEvidenceAuditReportQuery, StatusError),
		prometheusViolationSignal(ctx, q, "prometheus_alerts", cfg.OperationsPrometheusAlertsQuery, StatusWarn),
	}
}

func prometheusViolationSignal(ctx context.Context, q PrometheusQuerier, key, query string, violationStatus SignalStatus) Signal {
	query = strings.TrimSpace(query)
	details := map[string]any{"query_configured": query != ""}
	if query == "" {
		return Signal{
			Key:     key,
			Status:  StatusUnknown,
			Source:  "prometheus",
			Message: "Prometheus query is not configured for this signal",
			Details: details,
		}
	}
	value, found, err := q.QueryValue(ctx, query)
	if err != nil {
		return Signal{
			Key:     key,
			Status:  StatusError,
			Source:  "prometheus",
			Message: "Prometheus query failed",
			Details: details,
		}
	}
	if !found {
		return Signal{
			Key:     key,
			Status:  StatusUnknown,
			Source:  "prometheus",
			Message: "Prometheus query returned no samples",
			Details: details,
		}
	}
	details["value"] = value
	if value <= 0 {
		return Signal{
			Key:     key,
			Status:  StatusOK,
			Source:  "prometheus",
			Message: "Prometheus query reports no active violations",
			Details: details,
		}
	}
	return Signal{
		Key:     key,
		Status:  violationStatus,
		Source:  "prometheus",
		Message: "Prometheus query reports active violations",
		Details: details,
	}
}

type failedPrometheusQuerier struct {
	err error
}

func (f failedPrometheusQuerier) QueryValue(context.Context, string) (float64, bool, error) {
	return 0, false, f.err
}

type prometheusQueryResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	Data   struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
}

func (r prometheusQueryResponse) Value() (float64, bool, error) {
	switch r.Data.ResultType {
	case "scalar":
		return parsePrometheusScalar(r.Data.Result)
	case "vector":
		return parsePrometheusVector(r.Data.Result)
	default:
		return 0, false, fmt.Errorf("unsupported Prometheus resultType %q", r.Data.ResultType)
	}
}

func parsePrometheusScalar(raw json.RawMessage) (float64, bool, error) {
	var tuple []json.RawMessage
	if err := json.Unmarshal(raw, &tuple); err != nil {
		return 0, false, err
	}
	if len(tuple) < 2 {
		return 0, false, nil
	}
	value, err := parsePrometheusNumber(tuple[1])
	if err != nil {
		return 0, false, err
	}
	return value, true, nil
}

func parsePrometheusVector(raw json.RawMessage) (float64, bool, error) {
	var samples []struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &samples); err != nil {
		return 0, false, err
	}
	if len(samples) == 0 {
		return 0, false, nil
	}
	maxValue := math.Inf(-1)
	found := false
	for _, sample := range samples {
		if len(sample.Value) < 2 {
			continue
		}
		value, err := parsePrometheusNumber(sample.Value[1])
		if err != nil {
			return 0, false, err
		}
		if value > maxValue {
			maxValue = value
		}
		found = true
	}
	if !found {
		return 0, false, nil
	}
	return maxValue, true, nil
}

func parsePrometheusNumber(raw json.RawMessage) (float64, error) {
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return strconv.ParseFloat(asString, 64)
	}
	var asNumber float64
	if err := json.Unmarshal(raw, &asNumber); err != nil {
		return 0, err
	}
	return asNumber, nil
}

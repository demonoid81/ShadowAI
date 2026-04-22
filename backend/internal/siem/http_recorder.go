//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"time"
)

// HTTPRecorder — v1 SIEM sink: POST JSON envelope на configured
// endpoint. Fail-open: HTTP errors / timeouts увеличивают metrics,
// но не пропагируют в caller.
type HTTPRecorder struct {
	client      *http.Client
	endpoint    string
	bearerToken string
}

// NewHTTPRecorder. Если endpoint пустой — возвращает NoopRecorder-
// подобное поведение (Record no-op). Если insecureSkipVerify=true,
// проверка TLS-сертификата отключается — ТОЛЬКО для dev/test.
func NewHTTPRecorder(endpoint, bearerToken string, timeout time.Duration, insecureSkipVerify bool) *HTTPRecorder {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if insecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true // dev only — документировано в docs
	}
	return &HTTPRecorder{
		client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
		endpoint:    endpoint,
		bearerToken: bearerToken,
	}
}

// envelope — обёртка вокруг Event для sink'а. Позволяет в будущем
// легко добавить другие streams (policy_events, audit_logs) без
// изменения receiver configs.
type envelope struct {
	Source string `json:"source"`
	Stream string `json:"stream"`
	Event  Event  `json:"event"`
}

// Record отправляет event в SIEM. Не блокирует надолго (Client.Timeout).
// Ошибки уходят в metrics + local log (без секретов).
func (r *HTTPRecorder) Record(ctx context.Context, ev Event) {
	if r == nil || r.endpoint == "" {
		return
	}
	body, err := json.Marshal(envelope{
		Source: "shadowai",
		Stream: "admin_event_logs",
		Event:  ev,
	})
	if err != nil {
		SIEMFailTotal.WithLabelValues("http").Inc()
		log.Printf("siem: marshal failed: %v", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		SIEMFailTotal.WithLabelValues("http").Inc()
		log.Printf("siem: build request failed endpoint=%s err=%v", sinkHost(r.endpoint), err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if r.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.bearerToken)
	}

	start := time.Now()
	resp, err := r.client.Do(req)
	SIEMLatencySeconds.WithLabelValues("http").Observe(time.Since(start).Seconds())
	SIEMRequestsTotal.WithLabelValues("http").Inc()

	if err != nil {
		if isTimeout(err) {
			SIEMTimeoutTotal.WithLabelValues("http").Inc()
			log.Printf("siem: timeout endpoint=%s action=%s", sinkHost(r.endpoint), ev.Action)
		} else {
			SIEMFailTotal.WithLabelValues("http").Inc()
			log.Printf("siem: post failed endpoint=%s action=%s err=%v", sinkHost(r.endpoint), ev.Action, err)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		SIEMFailTotal.WithLabelValues("http").Inc()
		log.Printf("siem: non-2xx endpoint=%s action=%s status=%d", sinkHost(r.endpoint), ev.Action, resp.StatusCode)
	}
}

// sinkHost извлекает host из endpoint для безопасного logging
// (без query params / bearer token в error logs). Если URL
// invalid — возвращает "<invalid>".
func sinkHost(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "<invalid>"
	}
	return u.Host
}

// isTimeout распознаёт как context deadline, так и net timeout.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var te interface{ Timeout() bool }
	if errors.As(err, &te) && te.Timeout() {
		return true
	}
	return false
}

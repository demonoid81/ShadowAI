package proxy

import (
	"math/rand"
	"net"
	"net/http"
	"time"
)

// doWithRetry executes buildReq+client.Do with exponential backoff on transient errors.
// maxRetries is the number of additional attempts (e.g. 2 means up to 3 total).
func doWithRetry(client *http.Client, buildReq func() (*http.Request, error), maxRetries int) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			sleep := retryBackoff(attempt)
			time.Sleep(sleep)
		}

		var req *http.Request
		req, err = buildReq()
		if err != nil {
			return nil, err // build error is not retryable
		}

		resp, err = client.Do(req)
		if err != nil {
			if isRetryableNetError(err) && attempt < maxRetries {
				continue
			}
			return nil, err
		}

		if isRetryableStatus(resp.StatusCode) && attempt < maxRetries {
			resp.Body.Close()
			continue
		}

		return resp, nil
	}

	// Return last response/error
	if resp != nil {
		return resp, nil
	}
	return nil, err
}

// retryBackoff returns backoff duration for given attempt (1-based).
// Base delays: 500ms, 1500ms with ±25% jitter.
func retryBackoff(attempt int) time.Duration {
	baseMs := []int{500, 1500}
	idx := attempt - 1
	if idx >= len(baseMs) {
		idx = len(baseMs) - 1
	}
	base := float64(baseMs[idx])
	jitter := base * 0.25 * (2*rand.Float64() - 1) // ±25%
	return time.Duration(base+jitter) * time.Millisecond
}

// isRetryableStatus returns true for HTTP status codes worth retrying.
func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, // 429
		http.StatusInternalServerError,  // 500
		http.StatusBadGateway,           // 502
		http.StatusServiceUnavailable,   // 503
		http.StatusGatewayTimeout:       // 504
		return true
	}
	return false
}

// isRetryableNetError checks if the error is a transient network error.
func isRetryableNetError(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	if opErr, ok := err.(*net.OpError); ok {
		_ = opErr
		return true // connection refused, etc.
	}
	return false
}

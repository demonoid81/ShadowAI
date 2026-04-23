package chain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPImmuDBClient — minimal immudb client over REST API.
// Implements ImmuDBClient interface without requiring the full immudb SDK.
// Connects to immudb's built-in REST endpoint (enabled by default on
// the same port with /path prefix or a dedicated REST port).
//
// immudb REST v1 endpoints used:
//   POST /auth/login    → Bearer token
//   POST /db/use/{db}  → switch database
//   POST /db/set       → set key/value (base64)
//   POST /db/get       → get value by key (base64)
//
// For production: ensure immudb is started with REST API enabled.
// See https://docs.immudb.io/master/immudb/ for deployment details.
type HTTPImmuDBClient struct {
	baseURL  string
	database string
	token    string
	httpC    *http.Client
}

// DialImmuDB connects to immudb REST API, authenticates, and selects the database.
// addr format: "host:port" (e.g. "127.0.0.1:3323" for default REST port).
// Returns a ready-to-use client or an error if connection/auth fails.
// Callers should call log.Fatalf if this returns error in prod.
func DialImmuDB(ctx context.Context, addr, username, password, database string) (*HTTPImmuDBClient, error) {
	baseURL := "http://" + addr
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		baseURL = addr
	}
	c := &HTTPImmuDBClient{
		baseURL:  strings.TrimRight(baseURL, "/"),
		database: database,
		httpC: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	// Authenticate.
	if err := c.login(ctx, username, password); err != nil {
		return nil, fmt.Errorf("immudb dial: login: %w", err)
	}
	// Select database.
	if err := c.useDatabase(ctx, database); err != nil {
		return nil, fmt.Errorf("immudb dial: use database %s: %w", database, err)
	}
	return c, nil
}

func (c *HTTPImmuDBClient) login(ctx context.Context, user, pass string) error {
	body, _ := json.Marshal(map[string]string{"user": user, "password": pass})
	resp, err := c.doJSON(ctx, "POST", "/auth/login", body)
	if err != nil {
		return err
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("login response: %w", err)
	}
	if result.Token == "" {
		return fmt.Errorf("login: empty token in response")
	}
	c.token = result.Token
	return nil
}

func (c *HTTPImmuDBClient) useDatabase(ctx context.Context, db string) error {
	_, err := c.doJSON(ctx, "GET", "/db/use/"+db, nil)
	return err
}

// Set stores value under key. Returns transaction ID.
func (c *HTTPImmuDBClient) Set(ctx context.Context, key string, value []byte) (uint64, error) {
	body, _ := json.Marshal(map[string]any{
		"KVs": []map[string]string{
			{
				"key":   base64.StdEncoding.EncodeToString([]byte(key)),
				"value": base64.StdEncoding.EncodeToString(value),
			},
		},
	})
	resp, err := c.doJSON(ctx, "POST", "/db/set", body)
	if err != nil {
		return 0, err
	}
	var result struct {
		ID uint64 `json:"id"`
	}
	_ = json.Unmarshal(resp, &result)
	return result.ID, nil
}

// Get retrieves value by key.
func (c *HTTPImmuDBClient) Get(ctx context.Context, key string) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{
		"key": base64.StdEncoding.EncodeToString([]byte(key)),
	})
	resp, err := c.doJSON(ctx, "POST", "/db/get", body)
	if err != nil {
		return nil, err
	}
	var result struct {
		Value string `json:"value"` // base64
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("get response: %w", err)
	}
	if result.Value == "" {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return base64.StdEncoding.DecodeString(result.Value)
}

func (c *HTTPImmuDBClient) doJSON(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	url := c.baseURL + path
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("request build: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpC.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("immudb %s %s: status %d: %s", method, path, resp.StatusCode, respBody)
	}
	return respBody, nil
}

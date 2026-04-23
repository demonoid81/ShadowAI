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

// HTTPImmuDBClient — immudb REST client compatible with immugw REST proxy.
//
// API reference: https://docs.immudb.io/0.8.1/immugw/curl.html
//
// Endpoint prefix: /v1/immurestproxy (immugw default).
// Configurable via APIPrefix for deployments using a different base path.
//
// Authentication: POST /v1/immurestproxy/login with base64-encoded credentials
// → Bearer token in subsequent requests.
//
// To deploy: run immugw alongside immudb, expose REST on its port (default 8080).
// Or run immudb 2.x with built-in REST and set APIPrefix accordingly.
type HTTPImmuDBClient struct {
	baseURL   string
	database  string
	apiPrefix string
	token     string
	httpC     *http.Client
}

// ImmuDBOptions configures the immudb REST client.
type ImmuDBOptions struct {
	// APIPrefix is the REST API base path. Default: "/v1/immurestproxy".
	// For immudb 2.x built-in REST use "/api/v2".
	APIPrefix string
}

// DefaultImmuDBOptions returns options for immugw (most common deployment).
func DefaultImmuDBOptions() ImmuDBOptions {
	return ImmuDBOptions{APIPrefix: "/v1/immurestproxy"}
}

// DialImmuDB connects to immudb via REST proxy (immugw), authenticates, and
// selects the database. Returns a ready-to-use ImmuDBClient or an error.
// Callers should log.Fatalf if this fails in prod (no silent NoOp fallback).
//
// addr: "host:port" or full URL.
// For immugw defaults: addr="127.0.0.1:8080", options=DefaultImmuDBOptions().
func DialImmuDB(ctx context.Context, addr, username, password, database string) (*HTTPImmuDBClient, error) {
	return DialImmuDBWithOptions(ctx, addr, username, password, database, DefaultImmuDBOptions())
}

// DialImmuDBWithOptions is like DialImmuDB with explicit options.
func DialImmuDBWithOptions(ctx context.Context, addr, username, password, database string, opts ImmuDBOptions) (*HTTPImmuDBClient, error) {
	baseURL := addr
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		baseURL = "http://" + addr
	}
	apiPrefix := opts.APIPrefix
	if apiPrefix == "" {
		apiPrefix = "/v1/immurestproxy"
	}
	c := &HTTPImmuDBClient{
		baseURL:   strings.TrimRight(baseURL, "/"),
		database:  database,
		apiPrefix: apiPrefix,
		httpC: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	if err := c.login(ctx, username, password); err != nil {
		return nil, fmt.Errorf("immudb dial: login: %w", err)
	}
	if err := c.useDatabase(ctx, database); err != nil {
		return nil, fmt.Errorf("immudb dial: use database %s: %w", database, err)
	}
	return c, nil
}

// login: POST /v1/immurestproxy/login
// Fields user and password are base64-encoded per immugw spec.
func (c *HTTPImmuDBClient) login(ctx context.Context, user, pass string) error {
	body, _ := json.Marshal(map[string]string{
		"user":     base64.StdEncoding.EncodeToString([]byte(user)),
		"password": base64.StdEncoding.EncodeToString([]byte(pass)),
	})
	resp, err := c.doJSON(ctx, "POST", c.apiPrefix+"/login", body)
	if err != nil {
		return err
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("login response parse: %w", err)
	}
	if result.Token == "" {
		return fmt.Errorf("login: empty token in response")
	}
	c.token = result.Token
	return nil
}

// useDatabase: GET /v1/immurestproxy/user/use/{database}
// Switches the active database context.
func (c *HTTPImmuDBClient) useDatabase(ctx context.Context, db string) error {
	_, err := c.doJSON(ctx, "GET", c.apiPrefix+"/user/use/"+db, nil)
	return err
}

// Set: POST /v1/immurestproxy/item
// key and value are base64-encoded per immugw spec.
// Returns transaction ID from response "index" field.
func (c *HTTPImmuDBClient) Set(ctx context.Context, key string, value []byte) (uint64, error) {
	body, _ := json.Marshal(map[string]string{
		"key":   base64.StdEncoding.EncodeToString([]byte(key)),
		"value": base64.StdEncoding.EncodeToString(value),
	})
	resp, err := c.doJSON(ctx, "POST", c.apiPrefix+"/item", body)
	if err != nil {
		return 0, err
	}
	var result struct {
		Index uint64 `json:"index"` // immugw v0.8 returns "index"
		ID    uint64 `json:"id"`    // some versions use "id"
	}
	_ = json.Unmarshal(resp, &result)
	if result.ID > 0 {
		return result.ID, nil
	}
	return result.Index, nil
}

// Get: POST /v1/immurestproxy/item/get
// key is base64-encoded per immugw spec.
// Returns decoded value bytes.
func (c *HTTPImmuDBClient) Get(ctx context.Context, key string) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{
		"key": base64.StdEncoding.EncodeToString([]byte(key)),
	})
	resp, err := c.doJSON(ctx, "POST", c.apiPrefix+"/item/get", body)
	if err != nil {
		return nil, err
	}
	var result struct {
		Value string `json:"value"` // base64
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("get response parse: %w", err)
	}
	if result.Value == "" {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	decoded, err := base64.StdEncoding.DecodeString(result.Value)
	if err != nil {
		return nil, fmt.Errorf("decode value: %w", err)
	}
	return decoded, nil
}

func (c *HTTPImmuDBClient) doJSON(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	url := c.baseURL + path
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request %s %s: %w", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
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
		return nil, fmt.Errorf("immudb %s %s → status %d: %s", method, path, resp.StatusCode, respBody)
	}
	return respBody, nil
}

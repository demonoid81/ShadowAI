package chain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ImmuDBRESTProfile selects the REST API variant.
//
// immugw_v1 — immugw REST proxy (v0.8/v0.9). POST /v1/immurestproxy/* with
// base64-encoded credentials and Bearer token authentication.
//
// immudb_v2 — immudb 1.9+ built-in REST at :8080/api/v2. Session-based auth
// (POST /api/v2/authorization/session/open → sessionid header). No separate
// "use database" step; database selected during session open.
type ImmuDBRESTProfile string

const (
	// ProfileImmugwV1 is the immugw REST proxy profile (default).
	ProfileImmugwV1 ImmuDBRESTProfile = "immugw_v1"
	// ProfileImmudbV2 is the immudb 2.x built-in REST profile.
	ProfileImmudbV2 ImmuDBRESTProfile = "immudb_v2"
)

// ParseImmuDBRESTProfile normalises and validates a profile string.
// Empty string → ProfileImmugwV1 (backward-compatible default).
// Returns an error for any unrecognised value so callers fail loudly on typos.
func ParseImmuDBRESTProfile(s string) (ImmuDBRESTProfile, error) {
	switch ImmuDBRESTProfile(s) {
	case "", ProfileImmugwV1:
		return ProfileImmugwV1, nil
	case ProfileImmudbV2:
		return ProfileImmudbV2, nil
	default:
		return "", fmt.Errorf("unknown immudb REST profile %q: must be %q or %q",
			s, ProfileImmugwV1, ProfileImmudbV2)
	}
}

// HTTPImmuDBClient — immudb REST client supporting immugw v1 and immudb v2 profiles.
//
// Select the profile via ImmuDBOptions.Profile when calling DialImmuDBWithOptions.
// The zero value uses ProfileImmugwV1 (backwards-compatible default).
type HTTPImmuDBClient struct {
	baseURL   string
	database  string
	profile   ImmuDBRESTProfile
	apiPrefix string
	token     string    // ProfileImmugwV1: Bearer token
	sessionID string    // ProfileImmudbV2: session ID
	httpC     *http.Client
}

// ImmuDBOptions configures the immudb REST client.
type ImmuDBOptions struct {
	// Profile selects the REST API variant. Default: ProfileImmugwV1.
	// Use ParseImmuDBRESTProfile to validate user-supplied strings.
	Profile ImmuDBRESTProfile
	// APIPrefix overrides the REST API base path for ProfileImmugwV1.
	// Ignored for ProfileImmudbV2 — that profile uses absolute /api/v2/...
	// paths that are not configurable (built-in immudb REST server).
	// If empty, defaults to "/v1/immurestproxy" for ProfileImmugwV1.
	APIPrefix string
}

// DefaultImmuDBOptions returns options for immugw (most common deployment).
func DefaultImmuDBOptions() ImmuDBOptions {
	return ImmuDBOptions{Profile: ProfileImmugwV1}
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

	profile, err := ParseImmuDBRESTProfile(string(opts.Profile))
	if err != nil {
		return nil, fmt.Errorf("immudb dial: %w", err)
	}

	apiPrefix := opts.APIPrefix
	if apiPrefix == "" && profile == ProfileImmugwV1 {
		apiPrefix = "/v1/immurestproxy"
	}
	// ProfileImmudbV2 uses absolute /api/v2/... paths — APIPrefix is ignored.

	c := &HTTPImmuDBClient{
		baseURL:   strings.TrimRight(baseURL, "/"),
		database:  database,
		profile:   profile,
		apiPrefix: apiPrefix,
		httpC:     &http.Client{Timeout: 10 * time.Second},
	}

	switch profile {
	case ProfileImmudbV2:
		if err := c.loginV2(ctx, username, password, database); err != nil {
			return nil, fmt.Errorf("immudb dial: login: %w", err)
		}
	default: // ProfileImmugwV1
		if err := c.loginV1(ctx, username, password); err != nil {
			return nil, fmt.Errorf("immudb dial: login: %w", err)
		}
		if err := c.useDatabase(ctx, database); err != nil {
			return nil, fmt.Errorf("immudb dial: use database %s: %w", database, err)
		}
	}

	return c, nil
}

// loginV2: POST /api/v2/authorization/session/open
// Plain JSON credentials (not base64). Database selected in auth request.
// Response: {"sessionID":"..."}. Subsequent requests use "sessionid: <id>" header.
func (c *HTTPImmuDBClient) loginV2(ctx context.Context, user, pass, database string) error {
	body, _ := json.Marshal(map[string]string{
		"username": user,
		"password": pass,
		"database": database,
	})
	resp, err := c.doJSON(ctx, "POST", "/api/v2/authorization/session/open", body)
	if err != nil {
		return err
	}
	var result struct {
		SessionID string `json:"sessionID"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("login v2 response parse: %w", err)
	}
	if result.SessionID == "" {
		return fmt.Errorf("login v2: empty sessionID in response")
	}
	c.sessionID = result.SessionID
	return nil
}

// loginV1: POST /v1/immurestproxy/login
// Fields user and password are base64-encoded per immugw spec.
func (c *HTTPImmuDBClient) loginV1(ctx context.Context, user, pass string) error {
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

// useDatabase: GET /v1/immurestproxy/user/use/{database} (immugw_v1 only).
func (c *HTTPImmuDBClient) useDatabase(ctx context.Context, db string) error {
	_, err := c.doJSON(ctx, "GET", c.apiPrefix+"/user/use/"+db, nil)
	return err
}

// Set stores key→value in immudb. Returns the transaction ID.
func (c *HTTPImmuDBClient) Set(ctx context.Context, key string, value []byte) (uint64, error) {
	if c.profile == ProfileImmudbV2 {
		return c.setV2(ctx, key, value)
	}
	return c.setV1(ctx, key, value)
}

// setV2: POST /api/v2/db/set
// Body: {"KVs":[{"key":"b64key","value":"b64value"}]}
// Response: {"id":"txID",...}
func (c *HTTPImmuDBClient) setV2(ctx context.Context, key string, value []byte) (uint64, error) {
	body, _ := json.Marshal(map[string]any{
		"KVs": []map[string]string{
			{
				"key":   base64.StdEncoding.EncodeToString([]byte(key)),
				"value": base64.StdEncoding.EncodeToString(value),
			},
		},
	})
	resp, err := c.doJSON(ctx, "POST", "/api/v2/db/set", body)
	if err != nil {
		return 0, err
	}
	var result struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(resp, &result)
	if result.ID == "" {
		return 0, nil
	}
	txID, _ := strconv.ParseUint(result.ID, 10, 64)
	return txID, nil
}

// setV1: POST /v1/immurestproxy/item (immugw_v1).
// key and value are base64-encoded per immugw spec.
func (c *HTTPImmuDBClient) setV1(ctx context.Context, key string, value []byte) (uint64, error) {
	body, _ := json.Marshal(map[string]string{
		"key":   base64.StdEncoding.EncodeToString([]byte(key)),
		"value": base64.StdEncoding.EncodeToString(value),
	})
	resp, err := c.doJSON(ctx, "POST", c.apiPrefix+"/item", body)
	if err != nil {
		return 0, err
	}
	var result struct {
		Index uint64 `json:"index"`
		ID    uint64 `json:"id"`
	}
	_ = json.Unmarshal(resp, &result)
	if result.ID > 0 {
		return result.ID, nil
	}
	return result.Index, nil
}

// Get retrieves the latest value for key from immudb.
func (c *HTTPImmuDBClient) Get(ctx context.Context, key string) ([]byte, error) {
	if c.profile == ProfileImmudbV2 {
		return c.getV2(ctx, key)
	}
	return c.getV1(ctx, key)
}

// getV2: POST /api/v2/db/history with limit:1 desc:true.
// Returns the most recent version of the value for the given key.
// immudb v2 REST has no direct "get by key" endpoint; history with desc:true
// returns the latest revision as the first entry.
func (c *HTTPImmuDBClient) getV2(ctx context.Context, key string) ([]byte, error) {
	body, _ := json.Marshal(map[string]any{
		"key":   base64.StdEncoding.EncodeToString([]byte(key)),
		"limit": 1,
		"desc":  true,
	})
	resp, err := c.doJSON(ctx, "POST", "/api/v2/db/history", body)
	if err != nil {
		return nil, err
	}
	var result struct {
		Entries []struct {
			Value string `json:"value"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("get v2 response parse: %w", err)
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	decoded, err := base64.StdEncoding.DecodeString(result.Entries[0].Value)
	if err != nil {
		return nil, fmt.Errorf("decode value: %w", err)
	}
	return decoded, nil
}

// getV1: POST /v1/immurestproxy/item/get (immugw_v1).
// key is base64-encoded per immugw spec.
func (c *HTTPImmuDBClient) getV1(ctx context.Context, key string) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{
		"key": base64.StdEncoding.EncodeToString([]byte(key)),
	})
	resp, err := c.doJSON(ctx, "POST", c.apiPrefix+"/item/get", body)
	if err != nil {
		return nil, err
	}
	var result struct {
		Value string `json:"value"`
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
	if c.sessionID != "" {
		req.Header.Set("sessionid", c.sessionID)
	} else if c.token != "" {
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

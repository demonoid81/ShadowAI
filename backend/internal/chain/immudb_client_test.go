package chain

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockImmugw simulates an immugw REST server for unit tests.
// Validates correct endpoint paths, auth header usage, base64 encoding.
type mockImmugw struct {
	t     *testing.T
	token string
	store map[string][]byte
}

func newMockImmugw(t *testing.T) (*mockImmugw, *httptest.Server) {
	t.Helper()
	m := &mockImmugw{
		t:     t,
		token: "test-bearer-token",
		store: make(map[string][]byte),
	}
	srv := httptest.NewServer(m)
	return m, srv
}

func (m *mockImmugw) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == "POST" && r.URL.Path == "/v1/immurestproxy/login":
		m.handleLogin(w, r)
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/immurestproxy/user/use/"):
		m.handleUseDB(w, r)
	case r.Method == "POST" && r.URL.Path == "/v1/immurestproxy/item":
		m.handleSet(w, r)
	case r.Method == "POST" && r.URL.Path == "/v1/immurestproxy/item/get":
		m.handleGet(w, r)
	default:
		m.t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		http.Error(w, "not found", 404)
	}
}

func (m *mockImmugw) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	// Validate base64 encoding of credentials.
	userBytes, err1 := base64.StdEncoding.DecodeString(body.User)
	passBytes, err2 := base64.StdEncoding.DecodeString(body.Password)
	if err1 != nil || err2 != nil {
		m.t.Errorf("login: credentials not base64 encoded (user_err=%v pass_err=%v)", err1, err2)
	}
	if string(userBytes) != "admin" || string(passBytes) != "password" {
		http.Error(w, "unauthorized", 401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": m.token})
}

func (m *mockImmugw) handleUseDB(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(200)
}

func (m *mockImmugw) handleSet(w http.ResponseWriter, r *http.Request) {
	if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") {
		m.t.Errorf("set: missing Bearer token, got: %q", auth)
		http.Error(w, "unauthorized", 401)
		return
	}
	var body struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	keyBytes, _ := base64.StdEncoding.DecodeString(body.Key)
	valBytes, _ := base64.StdEncoding.DecodeString(body.Value)
	m.store[string(keyBytes)] = valBytes
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]uint64{"index": 42})
}

func (m *mockImmugw) handleGet(w http.ResponseWriter, r *http.Request) {
	if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") {
		m.t.Errorf("get: missing Bearer token, got: %q", auth)
		http.Error(w, "unauthorized", 401)
		return
	}
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	keyBytes, _ := base64.StdEncoding.DecodeString(body.Key)
	val, ok := m.store[string(keyBytes)]
	if !ok {
		http.Error(w, `{"error":"key not found"}`, 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"key":   body.Key,
		"value": base64.StdEncoding.EncodeToString(val),
	})
}

// TestHTTPImmuDBClient_Login_UsesCorrectPath verifies /v1/immurestproxy/login.
func TestHTTPImmuDBClient_Login_UsesCorrectPath(t *testing.T) {
	_, srv := newMockImmugw(t)
	defer srv.Close()

	c, err := DialImmuDB(context.Background(), srv.URL, "admin", "password", "shadowai")
	if err != nil {
		t.Fatalf("DialImmuDB: %v", err)
	}
	if c.token != "test-bearer-token" {
		t.Errorf("token = %q, want test-bearer-token", c.token)
	}
}

// TestHTTPImmuDBClient_Set_SetsWithBearerAndBase64.
func TestHTTPImmuDBClient_Set_SetsWithBearerAndBase64(t *testing.T) {
	m, srv := newMockImmugw(t)
	defer srv.Close()

	c, _ := DialImmuDB(context.Background(), srv.URL, "admin", "password", "shadowai")
	txID, err := c.Set(context.Background(), "mykey", []byte("myvalue"))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if txID != 42 {
		t.Errorf("txID = %d, want 42", txID)
	}
	if string(m.store["mykey"]) != "myvalue" {
		t.Errorf("stored value = %q, want myvalue", m.store["mykey"])
	}
}

// TestHTTPImmuDBClient_Get_ReturnsValue.
func TestHTTPImmuDBClient_Get_ReturnsValue(t *testing.T) {
	m, srv := newMockImmugw(t)
	defer srv.Close()

	m.store["roundtrip-key"] = []byte("roundtrip-value")

	c, _ := DialImmuDB(context.Background(), srv.URL, "admin", "password", "shadowai")
	val, err := c.Get(context.Background(), "roundtrip-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(val) != "roundtrip-value" {
		t.Errorf("value = %q, want roundtrip-value", val)
	}
}

// TestHTTPImmuDBClient_Get_NonExistentKey_ReturnsError.
func TestHTTPImmuDBClient_Get_NonExistentKey_ReturnsError(t *testing.T) {
	_, srv := newMockImmugw(t)
	defer srv.Close()

	c, _ := DialImmuDB(context.Background(), srv.URL, "admin", "password", "shadowai")
	_, err := c.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent key, got nil")
	}
}

// TestHTTPImmuDBClient_AuthHeaderUsed verifies Bearer token is sent.
func TestHTTPImmuDBClient_AuthHeaderUsed(t *testing.T) {
	// Verified via mockImmugw.handleSet and handleGet — they call t.Errorf if
	// Authorization header is missing. This test exercises both operations.
	m, srv := newMockImmugw(t)
	defer srv.Close()

	c, _ := DialImmuDB(context.Background(), srv.URL, "admin", "password", "shadowai")
	_, _ = c.Set(context.Background(), "k", []byte("v"))
	_, _ = c.Get(context.Background(), "k")
	_ = m // t.Errorf called inside mockImmugw if auth is wrong
}

// TestHTTPImmuDBClient_Non2xx_ReturnsError.
func TestHTTPImmuDBClient_Non2xx_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "login") {
			w.WriteHeader(500)
			w.Write([]byte(`{"error":"internal server error"}`))
		} else {
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"token": "t"})
		}
	}))
	defer srv.Close()

	_, err := DialImmuDB(context.Background(), srv.URL, "admin", "password", "db")
	if err == nil {
		t.Error("expected error from 500 login response, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code 500: %v", err)
	}
}

// TestHTTPImmuDBClient_Set_Get_RoundTrip — end-to-end via mock gateway.
func TestHTTPImmuDBClient_Set_Get_RoundTrip(t *testing.T) {
	_, srv := newMockImmugw(t)
	defer srv.Close()

	c, err := DialImmuDB(context.Background(), srv.URL, "admin", "password", "shadowai")
	if err != nil {
		t.Fatalf("DialImmuDB: %v", err)
	}
	key := "shadowai/anchors/audit_logs/1-10"
	value := []byte(`{"v":1,"table":"audit_logs","seq_lo":1,"seq_hi":10}`)

	if _, err := c.Set(context.Background(), key, value); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := c.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("roundtrip mismatch: got %q, want %q", got, value)
	}
}

package middleware

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// security.go
// ---------------------------------------------------------------------------

func TestSecurityHeaders_SetsAllExpectedHeaders(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	expected := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":             "DENY",
		"Referrer-Policy":             "strict-origin-when-cross-origin",
		"Permissions-Policy":          "geolocation=(), microphone=(), camera=()",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":               "no-store",
		"Pragma":                       "no-cache",
		"Content-Security-Policy":     "default-src 'self'",
	}

	for header, want := range expected {
		got := rec.Header().Get(header)
		if got != want {
			t.Errorf("header %s = %q, want %q", header, got, want)
		}
	}
}

func TestSecurityHeaders_HSTS_OnlyForHTTPS_TLS(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{} // simulate TLS
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	hsts := rec.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("expected HSTS header for TLS request, got empty")
	}
}

func TestSecurityHeaders_HSTS_OnlyForHTTPS_XForwardedProto(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	hsts := rec.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("expected HSTS header when X-Forwarded-Proto=https, got empty")
	}
}

func TestSecurityHeaders_NoHSTS_ForHTTP(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	hsts := rec.Header().Get("Strict-Transport-Security")
	if hsts != "" {
		t.Errorf("expected no HSTS header for plain HTTP, got %q", hsts)
	}
}

func TestSecurityHeaders_DoesNotOverrideExistingCSP(t *testing.T) {
	customCSP := "default-src 'none'; script-src 'self'"
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	// Pre-set CSP before middleware runs.
	rec.Header().Set("Content-Security-Policy", customCSP)
	handler.ServeHTTP(rec, req)

	got := rec.Header().Get("Content-Security-Policy")
	if got != customCSP {
		t.Errorf("CSP = %q, want existing %q preserved", got, customCSP)
	}
}

func TestAPIServerTimeouts(t *testing.T) {
	read, write, idle, readHeader := APIServerTimeouts()

	if read != 15*time.Second {
		t.Errorf("read = %v, want 15s", read)
	}
	if write != 120*time.Second {
		t.Errorf("write = %v, want 120s", write)
	}
	if idle != 120*time.Second {
		t.Errorf("idle = %v, want 120s", idle)
	}
	if readHeader != 5*time.Second {
		t.Errorf("readHeader = %v, want 5s", readHeader)
	}
}

// ---------------------------------------------------------------------------
// cors.go
// ---------------------------------------------------------------------------

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"basic", "a, b, c", []string{"a", "b", "c"}},
		{"no spaces", "x,y,z", []string{"x", "y", "z"}},
		{"empty parts removed", "a,,b, ,c", []string{"a", "b", "c"}},
		{"single value", "only", []string{"only"}},
		{"all empty", ",,", nil},
		{"empty string", "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitCSV(tt.input)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("splitCSV(%q) = %v (len %d), want %v (len %d)", tt.input, got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitCSV(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ratelimit.go — pure functions
// ---------------------------------------------------------------------------

func TestConfigureTrustedProxies_ValidCIDRs(t *testing.T) {
	ConfigureTrustedProxies("10.0.0.0/8, 172.16.0.0/12")
	defer ConfigureTrustedProxies("") // cleanup

	if len(trustedProxyNets) != 2 {
		t.Fatalf("expected 2 trusted nets, got %d", len(trustedProxyNets))
	}
}

func TestConfigureTrustedProxies_IgnoresInvalid(t *testing.T) {
	ConfigureTrustedProxies("10.0.0.0/8, not-a-cidr, 192.168.0.0/16")
	defer ConfigureTrustedProxies("")

	if len(trustedProxyNets) != 2 {
		t.Fatalf("expected 2 trusted nets (invalid skipped), got %d", len(trustedProxyNets))
	}
}

func TestConfigureTrustedProxies_EmptyClears(t *testing.T) {
	ConfigureTrustedProxies("10.0.0.0/8")
	ConfigureTrustedProxies("")

	if trustedProxyNets != nil {
		t.Fatalf("expected nil after empty config, got %v", trustedProxyNets)
	}
}

func TestClientIP_NoTrustedProxy_ReturnsRemoteAddr(t *testing.T) {
	ConfigureTrustedProxies("")
	defer ConfigureTrustedProxies("")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	req.Header.Set("X-Real-IP", "1.2.3.4")

	got := ClientIP(req)
	if got != "203.0.113.1" {
		t.Errorf("ClientIP = %q, want %q", got, "203.0.113.1")
	}
}

func TestClientIP_TrustedProxy_UsesXRealIP(t *testing.T) {
	ConfigureTrustedProxies("10.0.0.0/8")
	defer ConfigureTrustedProxies("")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	req.Header.Set("X-Real-IP", "203.0.113.50")

	got := ClientIP(req)
	if got != "203.0.113.50" {
		t.Errorf("ClientIP = %q, want %q", got, "203.0.113.50")
	}
}

func TestClientIP_TrustedProxy_UsesXForwardedFor(t *testing.T) {
	ConfigureTrustedProxies("10.0.0.0/8")
	defer ConfigureTrustedProxies("")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 10.0.0.2")

	got := ClientIP(req)
	if got != "198.51.100.1" {
		t.Errorf("ClientIP = %q, want %q (first valid IP from XFF)", got, "198.51.100.1")
	}
}

func TestClientIP_TrustedProxy_XRealIPTakesPrecedence(t *testing.T) {
	ConfigureTrustedProxies("10.0.0.0/8")
	defer ConfigureTrustedProxies("")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	req.Header.Set("X-Real-IP", "1.1.1.1")
	req.Header.Set("X-Forwarded-For", "2.2.2.2")

	got := ClientIP(req)
	if got != "1.1.1.1" {
		t.Errorf("ClientIP = %q, want %q (X-Real-IP takes precedence)", got, "1.1.1.1")
	}
}

func TestParseIPFromHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.1.1:8080", "192.168.1.1"},
		{"192.168.1.1", "192.168.1.1"},
		{"::1", "::1"},
		{"[::1]:8080", "::1"},
		{"", ""},
		{"not-an-ip", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ip := parseIPFromHost(tt.input)
			got := ""
			if ip != nil {
				got = ip.String()
			}
			if got != tt.want {
				t.Errorf("parseIPFromHost(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseIPFromHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"single IP", "1.2.3.4", "1.2.3.4"},
		{"multiple IPs", "1.2.3.4, 5.6.7.8", "1.2.3.4"},
		{"with spaces", "  1.2.3.4 , 5.6.7.8 ", "1.2.3.4"},
		{"invalid first", "bogus, 5.6.7.8", "5.6.7.8"},
		{"all invalid", "bogus, also-bogus", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIPFromHeader(tt.header)
			if got != tt.want {
				t.Errorf("parseIPFromHeader(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestIsTrustedProxy(t *testing.T) {
	ConfigureTrustedProxies("10.0.0.0/8, 192.168.0.0/16")
	defer ConfigureTrustedProxies("")

	tests := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"192.168.1.1", true},
		{"172.16.0.1", false},
		{"8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := isTrustedProxy(net.ParseIP(tt.ip))
			if got != tt.want {
				t.Errorf("isTrustedProxy(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsTrustedProxy_EmptyList(t *testing.T) {
	ConfigureTrustedProxies("")

	if isTrustedProxy(net.ParseIP("10.0.0.1")) {
		t.Error("expected false when no trusted proxies configured")
	}
}

// ---------------------------------------------------------------------------
// logging.go
// ---------------------------------------------------------------------------

func TestLogging_CallsNextHandler(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := Logging(inner)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("inner handler was not called")
	}
}

func TestLogging_CapturesStatusCode(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	handler := Logging(inner)
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestStatusWriter_DefaultStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, status: 200}

	// Write body without calling WriteHeader — status should stay 200.
	_, _ = sw.Write([]byte("hello"))

	if sw.status != 200 {
		t.Errorf("default status = %d, want 200", sw.status)
	}
}

func TestStatusWriter_WriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, status: 200}

	sw.WriteHeader(http.StatusCreated)

	if sw.status != http.StatusCreated {
		t.Errorf("status = %d, want %d", sw.status, http.StatusCreated)
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("underlying recorder status = %d, want %d", rec.Code, http.StatusCreated)
	}
}

// ---------------------------------------------------------------------------
// recovery.go
// ---------------------------------------------------------------------------

func TestRecovery_NoPanic(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := Recovery(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "ok")
	}
}

func TestRecovery_PanicReturns500(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("something went wrong")
	})

	handler := Recovery(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestRecovery_PanicWithError(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(net.ErrClosed)
	})

	handler := Recovery(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

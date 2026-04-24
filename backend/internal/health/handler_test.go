package health

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLivenessHandler_AlwaysOK(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	LivenessHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("liveness: status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "ok") {
		t.Errorf("liveness: body = %q, want 'ok'", rr.Body.String())
	}
}

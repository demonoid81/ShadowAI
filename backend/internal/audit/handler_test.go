package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/shadowai/backend/internal/domain"
)

// recordingRepo захватывает параметры вызова .List для проверки, что
// handler корректно прокидывает has_shadow в repository-слой.
type recordingRepo struct {
	mu        sync.Mutex
	lastCall  listCall
	returnLog []domain.AuditLog
}

type listCall struct {
	limit, offset                              int
	userID, model, policyAction, hasShadow     string
}

func (r *recordingRepo) Insert(_ context.Context, _ *domain.AuditLog) error { return nil }

func (r *recordingRepo) List(_ context.Context, limit, offset int, userID, model, policyAction, hasShadow string) ([]domain.AuditLog, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastCall = listCall{limit, offset, userID, model, policyAction, hasShadow}
	return r.returnLog, len(r.returnLog), nil
}

// TestAuditHandler_HasShadow_Whitelist — PR-4.1: handler принимает только
// has_shadow=yes|no. Любое другое значение (включая "true"/"1"/мусор)
// нормализуется в "" (no-op в repository). Это fail-safe поведение:
// misconfig в UI или старый клиент не должны ломать list-endpoint.
func TestAuditHandler_HasShadow_Whitelist(t *testing.T) {
	cases := []struct {
		query    string
		expected string
	}{
		{"yes", "yes"},
		{"no", "no"},
		{"any", ""},
		{"", ""},
		{"1", ""},
		{"true", ""},
		{"garbage", ""},
	}

	for _, tc := range cases {
		repo := &recordingRepo{}
		svc := &Service{repo: repo}
		h := NewHandler(svc)

		req := httptest.NewRequest("GET", "/audit/logs?has_shadow="+tc.query, nil)
		rec := httptest.NewRecorder()
		h.List(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("has_shadow=%q: status = %d, want 200", tc.query, rec.Code)
			continue
		}
		if repo.lastCall.hasShadow != tc.expected {
			t.Errorf("has_shadow=%q → repository получил %q, want %q",
				tc.query, repo.lastCall.hasShadow, tc.expected)
		}
	}
}

// TestAuditHandler_HasShadow_ReachesRepo_EndToEnd — смоук-тест: handler
// корректно возвращает JSON с data/total, независимо от has_shadow.
func TestAuditHandler_HasShadow_ReachesRepo_EndToEnd(t *testing.T) {
	repo := &recordingRepo{
		returnLog: []domain.AuditLog{
			{ID: "1", UserID: "u", ShadowDecisionsJSON: `[{"inspector":"pii","action":"block"}]`},
		},
	}
	svc := &Service{repo: repo}
	h := NewHandler(svc)

	req := httptest.NewRequest("GET", "/audit/logs?has_shadow=yes", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	var body struct {
		Data  []domain.AuditLog `json:"data"`
		Total int               `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response не парсится: %v\nbody: %s", err, rec.Body.String())
	}
	if body.Total != 1 || len(body.Data) != 1 {
		t.Fatalf("total=%d data=%d, want 1/1", body.Total, len(body.Data))
	}
	if body.Data[0].ShadowDecisionsJSON == "" {
		t.Error("shadow_decisions_json теряется при сериализации response")
	}
}

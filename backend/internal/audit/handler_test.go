package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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

// PR-A stubs.
func (r *recordingRepo) PurgeOlderThan(_ context.Context, _ time.Time, _ int) (int, error) {
	return 0, nil
}
func (r *recordingRepo) RecordPurgeRun(_ context.Context, _ time.Time, _ int) error {
	return nil
}
func (r *recordingRepo) LastPurgeRun(_ context.Context) (*domain.PurgeRun, error) {
	return nil, nil
}
func (r *recordingRepo) TotalRowsPurged(_ context.Context) (int, error) {
	return 0, nil
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
		h := NewHandler(svc, PayloadModeRedacted, 30)

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

// TestAuditHandler_Status_ExposesConfig — Status endpoint отдаёт
// payload_mode/retention_days без secrets, + purge totals.
func TestAuditHandler_Status_ExposesConfig(t *testing.T) {
	repo := &recordingRepo{}
	svc := &Service{repo: repo}
	h := NewHandler(svc, PayloadModeRedacted, 30)

	req := httptest.NewRequest("GET", "/audit/status", nil)
	rec := httptest.NewRecorder()
	h.Status(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var body statusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.PayloadMode != "redacted" {
		t.Errorf("payload_mode=%q, want redacted", body.PayloadMode)
	}
	if body.RetentionDays != 30 {
		t.Errorf("retention_days=%d, want 30", body.RetentionDays)
	}
	if !body.SchedulerEnabled {
		t.Error("scheduler_enabled должен быть true при retention_days>0")
	}
	if body.LastPurgedAt != nil {
		t.Errorf("last_purged_at должен быть nil (ни одного purge ещё не было), got %v", body.LastPurgedAt)
	}
	if body.RowsPurgedTotal != 0 {
		t.Errorf("rows_purged_total=%d, want 0", body.RowsPurgedTotal)
	}
}

// TestAuditHandler_Status_NoPIILeak — проверяем, что Status НЕ
// пропускает DATABASE_URL, endpoints, api-keys и т.п.
func TestAuditHandler_Status_NoPIILeak(t *testing.T) {
	repo := &recordingRepo{}
	svc := &Service{repo: repo}
	h := NewHandler(svc, PayloadModeFull, 90)

	req := httptest.NewRequest("GET", "/audit/status", nil)
	rec := httptest.NewRecorder()
	h.Status(rec, req)

	body := rec.Body.String()
	for _, forbidden := range []string{"postgres://", "password", "sk-", "api_key", "database_url"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("status body содержит запрещённый токен %q: %s", forbidden, body)
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
	h := NewHandler(svc, PayloadModeRedacted, 30)

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

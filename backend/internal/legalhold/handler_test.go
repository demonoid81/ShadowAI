//go:build enterprise

package legalhold

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/domain"
)

type captureRecorder struct {
	events []adminaudit.Event
}

func (c *captureRecorder) Record(_ context.Context, ev adminaudit.Event) {
	c.events = append(c.events, ev)
}

func setupHandler(t *testing.T) (*Handler, *memRepo, *captureRecorder) {
	t.Helper()
	repo := &memRepo{}
	rec := &captureRecorder{}
	return NewHandler(NewService(repo), rec), repo, rec
}

func adminCtx(req *http.Request, actor string) *http.Request {
	return req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: actor, Role: auth.RoleAdmin, OrgID: domain.DefaultOrgID,
	}))
}

type stubUserOrgLookup struct {
	byID map[string]*domain.User
}

func (s stubUserOrgLookup) GetByID(_ context.Context, id string) (*domain.User, error) {
	if u := s.byID[id]; u != nil {
		return u, nil
	}
	return nil, ErrNotFound
}

func (s stubUserOrgLookup) GetByIDScoped(_ context.Context, id, orgID string) (*domain.User, error) {
	if u := s.byID[id]; u != nil && u.OrgID == orgID {
		return u, nil
	}
	return nil, ErrNotFound
}

// TestCreate_HappyPath — PR-L2.3: admin создаёт pending hold;
// event "apply_hold_requested" recorded. Hold ещё НЕ active — нужен
// approve другим admin'ом.
func TestCreate_HappyPath(t *testing.T) {
	h, repo, rec := setupHandler(t)
	body := `{"target_user_id":"u-target","case_ref":"case-42","reason":"litigation"}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin")
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if len(repo.holds) != 1 || repo.holds[0].Status != StatusPending || repo.holds[0].IsActive {
		t.Errorf("repo state = %+v (expected 1 pending+IsActive=false)", repo.holds)
	}
	if len(rec.events) != 1 || rec.events[0].Action != "apply_hold_requested" {
		t.Errorf("events = %+v (expected 1 apply_hold_requested)", rec.events)
	}
	if !rec.events[0].Success {
		t.Error("admin event success=false на happy path")
	}
	// status в metadata для SIEM-фильтра.
	meta := rec.events[0].Metadata.(map[string]any)
	if meta["status"] != "pending" {
		t.Errorf("metadata.status = %v, want pending", meta["status"])
	}
}

// TestCreate_NonAdmin_Forbidden.
func TestCreate_NonAdmin(t *testing.T) {
	h, _, _ := setupHandler(t)
	body := `{"target_user_id":"u-target","case_ref":"x","reason":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body))
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-1", Role: auth.RoleUser,
	}))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestCreate_TenantAdmin_CrossOrgDenied(t *testing.T) {
	h, repo, _ := setupHandler(t)
	h.userLookup = stubUserOrgLookup{byID: map[string]*domain.User{
		"u-target": {ID: "u-target", OrgID: "org-b", IsActive: true},
	}}
	body := `{"target_user_id":"u-target","case_ref":"x","reason":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body))
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-admin", Role: auth.RoleAdmin, OrgID: "org-a",
	}))
	w := httptest.NewRecorder()

	h.Create(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body=%s, want 404", w.Code, w.Body.String())
	}
	if len(repo.holds) != 0 {
		t.Fatalf("hold created for cross-org target: %+v", repo.holds)
	}
}

func TestCreate_TenantAdmin_SameOrgSetsHoldOrg(t *testing.T) {
	h, repo, _ := setupHandler(t)
	h.userLookup = stubUserOrgLookup{byID: map[string]*domain.User{
		"u-target": {ID: "u-target", OrgID: "org-a", IsActive: true},
	}}
	body := `{"target_user_id":"u-target","case_ref":"x","reason":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body))
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-admin", Role: auth.RoleAdmin, OrgID: "org-a",
	}))
	w := httptest.NewRecorder()

	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s, want 201", w.Code, w.Body.String())
	}
	if len(repo.holds) != 1 || repo.holds[0].OrgID != "org-a" {
		t.Fatalf("hold org mismatch: %+v", repo.holds)
	}
}

func TestCreate_DateRangeScope_HappyPath(t *testing.T) {
	h, repo, _ := setupHandler(t)
	body := `{
		"target_user_id":"u-target",
		"case_ref":"case-date",
		"reason":"date range",
		"scope_type":"date_range",
		"scope_date_from":"2026-04-01T00:00:00Z",
		"scope_date_to":"2026-04-30T23:59:59Z"
	}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin")
	w := httptest.NewRecorder()

	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if len(repo.holds) != 1 {
		t.Fatalf("holds = %d, want 1", len(repo.holds))
	}
	if repo.holds[0].ScopeType != ScopeDateRange {
		t.Fatalf("scope = %q, want %q", repo.holds[0].ScopeType, ScopeDateRange)
	}
	var resp holdResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ScopeType != ScopeDateRange {
		t.Fatalf("response scope = %q, want %q", resp.ScopeType, ScopeDateRange)
	}
}

func TestCreate_QueryScopeSuccess(t *testing.T) {
	h, repo, rec := setupHandler(t)
	body := `{
		"target_user_id":"u-target",
		"case_ref":"case-query",
		"reason":"query scope",
		"scope_type":"query_scope",
		"scope_query":{
			"v":1,
			"all":[
				{"field":"policy_action","op":"eq","value":"blocked"},
				{"field":"provider","op":"in","value":["openai","anthropic"]}
			]
		}
	}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin")
	w := httptest.NewRecorder()

	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if len(repo.holds) != 1 {
		t.Fatalf("holds = %d, want 1", len(repo.holds))
	}
	hold := repo.holds[0]
	if hold.ScopeType != ScopeQuery || hold.ScopeQueryHash == "" || hold.ScopeQueryJSON == "" || hold.ScopeQueryVersion != 1 {
		t.Fatalf("query scope fields not stored: %+v", hold)
	}
	if len(rec.events) != 1 {
		t.Fatalf("events = %d, want 1", len(rec.events))
	}
	meta := rec.events[0].Metadata.(map[string]any)
	if meta["selector_hash"] != hold.ScopeQueryHash || meta["scope_type"] != ScopeQuery {
		t.Fatalf("metadata = %+v, hold hash = %s", meta, hold.ScopeQueryHash)
	}
	if _, ok := meta["scope_query"]; ok {
		t.Fatalf("metadata must not contain raw selector: %+v", meta)
	}
	var resp holdResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.SelectorHash != hold.ScopeQueryHash {
		t.Fatalf("response selector_hash = %q, want %q", resp.SelectorHash, hold.ScopeQueryHash)
	}
}

func TestCreate_QueryScopeInvalidSelector(t *testing.T) {
	h, repo, rec := setupHandler(t)
	body := `{
		"target_user_id":"u-target",
		"case_ref":"case-query",
		"reason":"query scope",
		"scope_type":"query_scope",
		"scope_query":{"v":1,"field":"user_id","op":"eq","value":"u-other"}
	}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin")
	w := httptest.NewRecorder()

	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if len(repo.holds) != 0 {
		t.Fatalf("holds = %d, want 0", len(repo.holds))
	}
	if len(rec.events) != 1 {
		t.Fatalf("events = %d, want 1", len(rec.events))
	}
	meta := rec.events[0].Metadata.(map[string]any)
	if meta["error_code"] != "invalid_scope_query" {
		t.Fatalf("error_code = %v, want invalid_scope_query", meta["error_code"])
	}
}

func TestPreview_QueryScope_Success(t *testing.T) {
	h, repo, rec := setupHandler(t)
	oldest := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	newest := time.Date(2026, 4, 4, 11, 0, 0, 0, time.UTC)
	repo.previewStats = QueryScopePreviewStats{
		MatchedRows:     17,
		OldestCreatedAt: &oldest,
		NewestCreatedAt: &newest,
	}
	h.userLookup = stubUserOrgLookup{byID: map[string]*domain.User{
		"u-target": {ID: "u-target", OrgID: "org-a", IsActive: true},
	}}
	body := `{
		"target_user_id":"u-target",
		"scope_type":"query_scope",
		"scope_query":{
			"v":1,
			"all":[
				{"field":"provider","op":"in","value":["openai","anthropic"]},
				{"field":"policy_action","op":"eq","value":"blocked"}
			]
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/legal-holds/preview", bytes.NewBufferString(body))
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		UserID: "u-admin", Role: auth.RoleAdmin, OrgID: "org-a",
	}))
	w := httptest.NewRecorder()

	h.Preview(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if len(repo.holds) != 0 {
		t.Fatalf("preview created holds: %+v", repo.holds)
	}
	if repo.previewOrgID != "org-a" || repo.previewUserID != "u-target" {
		t.Fatalf("preview scope org=%q user=%q", repo.previewOrgID, repo.previewUserID)
	}
	var resp previewResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ScopeType != ScopeQuery || resp.SelectorHash == "" || resp.MatchedRows != 17 {
		t.Fatalf("response = %+v", resp)
	}
	if resp.OldestCreatedAt == nil || *resp.OldestCreatedAt != "2026-04-01T10:00:00Z" {
		t.Fatalf("oldest = %#v", resp.OldestCreatedAt)
	}
	if !bytes.Contains([]byte(resp.Explanation), []byte("target user rows where")) {
		t.Fatalf("explanation = %q", resp.Explanation)
	}
	if len(rec.events) != 1 || rec.events[0].Action != "preview_hold_scope" || !rec.events[0].Success {
		t.Fatalf("events = %+v", rec.events)
	}
	meta := rec.events[0].Metadata.(map[string]any)
	if meta["selector_hash"] != resp.SelectorHash || meta["matched_rows"] != 17 {
		t.Fatalf("metadata = %+v", meta)
	}
}

func TestPreview_QueryScope_InvalidSelector(t *testing.T) {
	h, repo, rec := setupHandler(t)
	body := `{
		"target_user_id":"u-target",
		"scope_type":"query_scope",
		"scope_query":{"v":1,"field":"org_id","op":"eq","value":"org-a"}
	}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/preview", bytes.NewBufferString(body)), "u-admin")
	w := httptest.NewRecorder()

	h.Preview(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if len(repo.holds) != 0 {
		t.Fatalf("preview created holds: %+v", repo.holds)
	}
	if len(rec.events) != 1 {
		t.Fatalf("events = %d, want 1", len(rec.events))
	}
	meta := rec.events[0].Metadata.(map[string]any)
	if meta["error_code"] != "invalid_scope_query" {
		t.Fatalf("error_code = %v, want invalid_scope_query", meta["error_code"])
	}
}

// TestCreate_Unauthenticated.
func TestCreate_Unauthenticated(t *testing.T) {
	h, _, _ := setupHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// TestCreate_Duplicate_409 — PR-L2.3: второй pending hold на того
// же user'а → 409 (partial-unique index "blocking per user" покрывает
// и pending, и active).
func TestCreate_Duplicate(t *testing.T) {
	h, _, rec := setupHandler(t)
	body := `{"target_user_id":"u-1","case_ref":"c1","reason":"r"}`
	w1 := httptest.NewRecorder()
	h.Create(w1, adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin"))
	if w1.Code != http.StatusCreated {
		t.Fatalf("first create status = %d", w1.Code)
	}
	w2 := httptest.NewRecorder()
	h.Create(w2, adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin"))
	if w2.Code != http.StatusConflict {
		t.Errorf("second create status = %d, want 409", w2.Code)
	}
	if len(rec.events) != 2 {
		t.Fatalf("events = %d, want 2", len(rec.events))
	}
	if rec.events[1].Success {
		t.Error("second event success=true, expected false")
	}
}

// TestCreate_ValidationError_400.
func TestCreate_ValidationError(t *testing.T) {
	h, _, _ := setupHandler(t)
	body := `{"target_user_id":"","case_ref":"","reason":""}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin")
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// TestRelease_HappyPath — PR-L5: под новый 4-eyes release workflow
// создать (pending) + approve (active) + release (request_release →
// release_pending) + approve_release (→ released).
func TestRelease_HappyPath(t *testing.T) {
	h, repo, rec := setupHandler(t)
	ctx := context.Background()
	seeded, _ := h.svc.CreateHold(ctx, "u-1", "c1", "r", "u-creator")
	if _, err := h.svc.Approve(ctx, seeded.ID, "u-approver"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Step 1: Release → active становится release_pending.
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/release", nil), "u-admin")
	req = mux.SetURLVars(req, map[string]string{"id": seeded.ID})
	w := httptest.NewRecorder()
	h.Release(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("release status = %d, body=%s", w.Code, w.Body.String())
	}
	if repo.holds[0].Status != StatusReleasePending {
		t.Errorf("hold state after Release = %+v (expected release_pending)", repo.holds[0])
	}

	// Step 2: ApproveRelease другим admin → release_pending становится released.
	req2 := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/approve-release", nil), "u-admin2")
	req2 = mux.SetURLVars(req2, map[string]string{"id": seeded.ID})
	w2 := httptest.NewRecorder()
	h.ApproveRelease(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("approve-release status = %d, body=%s", w2.Code, w2.Body.String())
	}
	if repo.holds[0].IsActive || repo.holds[0].Status != StatusReleased {
		t.Errorf("hold state after ApproveRelease = %+v (expected released)", repo.holds[0])
	}

	actions := actionsFromEvents(rec.events)
	if len(actions) != 2 || actions[0] != "request_release" || actions[1] != "approve_release" {
		t.Errorf("actions = %v, want [request_release, approve_release]", actions)
	}
}

// TestRelease_Idempotent — PR-L5: после полного цикла release (request +
// approve) второй Release возвращает 200 со status=already_released.
func TestRelease_Idempotent(t *testing.T) {
	h, _, _ := setupHandler(t)
	ctx := context.Background()
	seeded, _ := h.svc.CreateHold(ctx, "u-1", "c1", "r", "u-creator")
	if _, err := h.svc.Approve(ctx, seeded.ID, "u-approver"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// First release → release_pending.
	req1 := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/release", nil), "u-admin")
	req1 = mux.SetURLVars(req1, map[string]string{"id": seeded.ID})
	h.Release(httptest.NewRecorder(), req1)

	// Approve release → released (завершает цикл release).
	reqAR := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/approve-release", nil), "u-admin2")
	reqAR = mux.SetURLVars(reqAR, map[string]string{"id": seeded.ID})
	h.ApproveRelease(httptest.NewRecorder(), reqAR)

	// Second release — hold уже released → идемпотентный 200 already_released.
	req2 := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/release", nil), "u-admin")
	req2 = mux.SetURLVars(req2, map[string]string{"id": seeded.ID})
	w2 := httptest.NewRecorder()
	h.Release(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("second release status = %d, want 200 (idempotent)", w2.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(w2.Body.Bytes(), &resp)
	if resp["status"] != "already_released" {
		t.Errorf("response = %+v, want status=already_released", resp)
	}
}

// TestRelease_PendingReturns409_NotIdempotent — PR-L2.3 regression
// guard: release на pending НЕ должен возвращать 200 already_released
// (это collapse семантики). Должен быть 409 + error_code=
// pending_not_releasable с подсказкой operator'у использовать reject.
func TestRelease_PendingReturns409_NotIdempotent(t *testing.T) {
	h, _, rec := setupHandler(t)
	ctx := context.Background()
	seeded, _ := h.svc.CreateHold(ctx, "u-1", "c1", "r", "u-admin")
	// НЕ approve. Release на pending должен 409.

	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/release", nil), "u-admin")
	req = mux.SetURLVars(req, map[string]string{"id": seeded.ID})
	w := httptest.NewRecorder()
	h.Release(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (pending not releasable)", w.Code)
	}
	// Guard: body не должен утверждать already_released.
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] == "already_released" {
		t.Error("response заявляет already_released для pending hold — collapse семантики")
	}
	if len(rec.events) != 1 {
		t.Fatalf("events = %d, want 1", len(rec.events))
	}
	meta := rec.events[0].Metadata.(map[string]any)
	if meta["error_code"] != "pending_not_releasable" {
		t.Errorf("error_code = %v, want pending_not_releasable", meta["error_code"])
	}
	if rec.events[0].Success {
		t.Error("event success=true на 409 pending release — ложная запись успеха в audit")
	}
}

// TestRelease_NotFound.
func TestRelease_NotFound(t *testing.T) {
	h, _, _ := setupHandler(t)
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/h-missing/release", nil), "u-admin")
	req = mux.SetURLVars(req, map[string]string{"id": "h-missing"})
	w := httptest.NewRecorder()
	h.Release(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// TestList_HappyPath — PR-L2.3: List возвращает active + pending +
// released. Проверяем что counts в admin event разделены правильно.
func TestList_HappyPath(t *testing.T) {
	h, _, rec := setupHandler(t)
	ctx := context.Background()
	// 2 active, 1 pending.
	s1, _ := h.svc.CreateHold(ctx, "u-1", "c1", "r", "u-creator")
	_, _ = h.svc.Approve(ctx, s1.ID, "u-approver")
	s2, _ := h.svc.CreateHold(ctx, "u-2", "c2", "r", "u-creator")
	_, _ = h.svc.Approve(ctx, s2.ID, "u-approver")
	_, _ = h.svc.CreateHold(ctx, "u-3", "c3", "r", "u-creator") // pending

	req := adminCtx(httptest.NewRequest(http.MethodGet, "/api/legal-holds", nil), "u-admin")
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var out []holdResponse
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if len(out) != 3 {
		t.Errorf("list len = %d, want 3", len(out))
	}
	meta := rec.events[len(rec.events)-1].Metadata.(map[string]any)
	if meta["active_count"] != 2 {
		t.Errorf("active_count = %v, want 2", meta["active_count"])
	}
	if meta["pending_count"] != 1 {
		t.Errorf("pending_count = %v, want 1", meta["pending_count"])
	}
}

// TestCreate_MetadataHasHashNotRawCaseRef — PR-L1.1 privacy
// regression guard. admin_event metadata должна содержать
// case_ref_hash, а case_ref (raw) должен отсутствовать.
func TestCreate_MetadataHasHashNotRawCaseRef(t *testing.T) {
	h, _, rec := setupHandler(t)
	rawCaseRef := "SEC-INTERNAL-2026-SECRET-42"
	body := `{"target_user_id":"u-1","case_ref":"` + rawCaseRef + `","reason":"r"}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin")
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d", w.Code)
	}
	if len(rec.events) != 1 {
		t.Fatalf("events = %d", len(rec.events))
	}
	meta := rec.events[0].Metadata.(map[string]any)

	// Правильный ключ присутствует.
	hash, ok := meta["case_ref_hash"].(string)
	if !ok || hash == "" {
		t.Errorf("case_ref_hash missing/empty in metadata: %+v", meta)
	}
	// Длина hash = 16 hex chars (truncated SHA-256, 64 bit).
	if len(hash) != 16 {
		t.Errorf("case_ref_hash len = %d, want 16", len(hash))
	}

	// Raw case_ref НЕ должен присутствовать ни под одним ключом.
	for k, v := range meta {
		if s, ok := v.(string); ok && s == rawCaseRef {
			t.Errorf("raw case_ref leak through metadata[%q] = %q", k, s)
		}
	}
	if _, has := meta["case_ref"]; has {
		t.Error("metadata содержит raw 'case_ref' ключ")
	}
}

// TestCreate_ConflictEventHasHashNotRawCaseRef — privacy guard
// для 409 path: conflict event тоже должен содержать hash, не raw.
func TestCreate_ConflictEventHasHashNotRawCaseRef(t *testing.T) {
	h, _, rec := setupHandler(t)
	rawCaseRef := "DOJ-LEAKED-REFERENCE"
	body := `{"target_user_id":"u-1","case_ref":"` + rawCaseRef + `","reason":"r"}`
	// First create succeeds.
	h.Create(httptest.NewRecorder(), adminCtx(
		httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin"))
	// Second → 409 conflict.
	w := httptest.NewRecorder()
	h.Create(w, adminCtx(
		httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin"))

	if w.Code != http.StatusConflict {
		t.Fatalf("second create status = %d, want 409", w.Code)
	}
	if len(rec.events) != 2 {
		t.Fatalf("events = %d", len(rec.events))
	}
	conflictMeta := rec.events[1].Metadata.(map[string]any)
	// PR-L2.3: error_code renamed from "already_active" →
	// "already_blocking" (покрывает и pending, и active).
	if conflictMeta["error_code"] != "already_blocking" {
		t.Errorf("error_code = %v, want already_blocking", conflictMeta["error_code"])
	}
	if _, has := conflictMeta["case_ref"]; has {
		t.Error("conflict event содержит raw case_ref")
	}
	for k, v := range conflictMeta {
		if s, ok := v.(string); ok && s == rawCaseRef {
			t.Errorf("raw case_ref leak в conflict event metadata[%q]", k)
		}
	}
}

// TestCreate_ValidationError_GenericMessage — PR-L1.1 error split.
// Client не должен получать raw err.Error() с internal path.
func TestCreate_ValidationError_GenericMessage(t *testing.T) {
	h, _, rec := setupHandler(t)
	body := `{"target_user_id":"u-1","case_ref":"","reason":""}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin")
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}

	// Response body не должен содержать "legalhold:" prefix —
	// internal err string не должен leak'аться клиенту.
	bodyStr := w.Body.String()
	if bytes.Contains([]byte(bodyStr), []byte("legalhold:")) {
		t.Errorf("response leaks internal error string: %s", bodyStr)
	}

	// Admin event metadata содержит error_code, не raw message.
	meta := rec.events[0].Metadata.(map[string]any)
	if meta["error_code"] != "validation_failed" {
		t.Errorf("error_code = %v, want validation_failed", meta["error_code"])
	}
	if _, has := meta["error"]; has {
		// Старый shape {"error": "legalhold: ..."} — не должен
		// присутствовать после PR-L1.1.
		t.Error("metadata содержит legacy 'error' key вместо error_code")
	}
}

// TestCreate_NotConfigured_Returns503 — service без repo
// (nil Service.repo) → 503 + error_code=not_configured.
func TestCreate_NotConfigured_Returns503(t *testing.T) {
	rec := &captureRecorder{}
	h := NewHandler(&Service{repo: nil}, rec) // not configured
	body := `{"target_user_id":"u-1","case_ref":"c","reason":"r"}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(body)), "u-admin")
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if len(rec.events) != 1 {
		t.Fatalf("events = %d", len(rec.events))
	}
	meta := rec.events[0].Metadata.(map[string]any)
	if meta["error_code"] != "not_configured" {
		t.Errorf("error_code = %v, want not_configured", meta["error_code"])
	}
}

// TestRelease_HappyPath_MetadataHasHashOnly — privacy guard для
// release event. PR-L2.3: hold нужно approve перед release.
func TestRelease_HappyPath_MetadataHasHashOnly(t *testing.T) {
	h, _, rec := setupHandler(t)
	ctx := context.Background()
	rawCaseRef := "CFPB-PRIVATE-MATTER"
	seeded, _ := h.svc.CreateHold(ctx, "u-1", rawCaseRef, "r", "u-creator")
	if _, err := h.svc.Approve(ctx, seeded.ID, "u-approver"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/release", nil), "u-admin")
	req = mux.SetURLVars(req, map[string]string{"id": seeded.ID})
	h.Release(httptest.NewRecorder(), req)

	// seed через svc bypass handler, в rec только release event.
	if len(rec.events) != 1 {
		t.Fatalf("events = %d, want 1", len(rec.events))
	}
	meta := rec.events[0].Metadata.(map[string]any)
	if _, has := meta["case_ref"]; has {
		t.Error("release event содержит raw case_ref")
	}
	hash, _ := meta["case_ref_hash"].(string)
	if hash == "" || len(hash) != 16 {
		t.Errorf("case_ref_hash malformed: %q", hash)
	}
}

// TestTokenizer_UnkeyedDeterministic — unkeyed mode (dev fallback):
// одинаковый case_ref всегда даёт одинаковый token. Backward
// compat с PR-L1.1 SHA-256 behavior.
func TestTokenizer_UnkeyedDeterministic(t *testing.T) {
	tok := newTokenizer("")
	a := tok.Tokenize("SEC-2026-042")
	b := tok.Tokenize("SEC-2026-042")
	if a != b {
		t.Errorf("unkeyed not deterministic: %q vs %q", a, b)
	}
	if a == tok.Tokenize("SEC-2026-043") {
		t.Error("different case_refs produce same token")
	}
}

// TestTokenizer_KeyedDeterministic — PR-L1.2 HMAC path. Одинаковый
// secret+caseRef → одинаковый token (SIEM correlation).
func TestTokenizer_KeyedDeterministic(t *testing.T) {
	tok := newTokenizer("super-secret-key-for-hmac-32chars!")
	a := tok.Tokenize("SEC-2026-042")
	b := tok.Tokenize("SEC-2026-042")
	if a != b {
		t.Errorf("keyed not deterministic: %q vs %q", a, b)
	}
	if a == tok.Tokenize("SEC-2026-043") {
		t.Error("different case_refs produce same keyed token")
	}
}

// TestTokenizer_KeyedDiffersFromUnkeyed — PR-L1.2 regression guard:
// keyed token для того же caseRef ОТЛИЧАЕТСЯ от unkeyed. Это
// подтверждает, что secret реально примешивается — attacker с
// mirror dump'ом не может восстановить raw case_ref brute-force'ом
// (если secret secure).
func TestTokenizer_KeyedDiffersFromUnkeyed(t *testing.T) {
	unkeyed := newTokenizer("")
	keyed := newTokenizer("super-secret-key-for-hmac-32chars!")
	caseRef := "SEC-2026-042"
	if unkeyed.Tokenize(caseRef) == keyed.Tokenize(caseRef) {
		t.Error("keyed == unkeyed: secret not applied to HMAC")
	}
}

// TestTokenizer_DifferentSecretsProduceDifferentTokens — ротация
// ключа должна менять все tokens (если operator ротирует secret,
// SIEM-rules по token'ам сломаются — это осознанное поведение).
func TestTokenizer_DifferentSecretsProduceDifferentTokens(t *testing.T) {
	t1 := newTokenizer("secret-key-number-one-32chars!!!!")
	t2 := newTokenizer("secret-key-number-two-32chars!!!!")
	caseRef := "SEC-2026-042"
	if t1.Tokenize(caseRef) == t2.Tokenize(caseRef) {
		t.Error("different secrets produced same token")
	}
}

// TestTokenizer_TokenLength_16Hex — формат стабилен: 16 hex chars
// = 64 bit, одинаковый для unkeyed и keyed.
func TestTokenizer_TokenLength_16Hex(t *testing.T) {
	for name, tok := range map[string]*tokenizer{
		"unkeyed": newTokenizer(""),
		"keyed":   newTokenizer("super-secret-key-for-hmac-32chars!"),
	} {
		got := tok.Tokenize("any-case-ref")
		if len(got) != 16 {
			t.Errorf("%s: token len = %d, want 16 hex", name, len(got))
		}
	}
}

// TestTokenizer_ConcurrentUnkeyed_NoRace — PR-L1.3: `go test -race`
// regression guard. Два concurrent goroutines вызывают Tokenize()
// на unkeyed tokenizer. warning-once logic теперь защищена
// sync.Once, так что race detector должен молчать.
//
// Проверка rotates через t.Parallel + параллельный fan-out.
func TestTokenizer_ConcurrentUnkeyed_NoRace(t *testing.T) {
	tok := newTokenizer("")
	const workers = 32
	start := make(chan struct{})
	done := make(chan struct{}, workers)
	for i := 0; i < workers; i++ {
		go func() {
			<-start
			_ = tok.Tokenize("SEC-2026-042")
			done <- struct{}{}
		}()
	}
	close(start)
	for i := 0; i < workers; i++ {
		<-done
	}
	// Explicit re-call чтобы убедиться, что warning не emit'ит
	// ошибку на повторном calls (sync.Once уже сработал).
	_ = tok.Tokenize("SEC-2026-043")
}

// TestNewHandlerWithSecret_UsesKeyed — integration: Handler созданный
// с secret использует keyed tokenizer, не plain.
func TestNewHandlerWithSecret_UsesKeyed(t *testing.T) {
	repo := &memRepo{}
	rec := &captureRecorder{}
	secret := "super-secret-key-for-hmac-32chars!"
	h := NewHandlerWithSecret(NewService(repo), rec, secret)

	caseRef := "SEC-2026-042"
	rawBody := `{"target_user_id":"u-1","case_ref":"` + caseRef + `","reason":"r"}`
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds", bytes.NewBufferString(rawBody)), "u-admin")
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d", w.Code)
	}
	meta := rec.events[0].Metadata.(map[string]any)
	gotToken, _ := meta["case_ref_hash"].(string)

	// Token должен совпадать с тем, что keyed tokenizer вернёт
	// напрямую.
	wantToken := newTokenizer(secret).Tokenize(caseRef)
	if gotToken != wantToken {
		t.Errorf("handler token = %q, want keyed tokenizer output %q", gotToken, wantToken)
	}
	// И должен ОТЛИЧАТЬСЯ от unkeyed (proof того, что secret работает).
	if gotToken == newTokenizer("").Tokenize(caseRef) {
		t.Error("handler с secret сгенерил unkeyed token")
	}
}

func actionsFromEvents(events []adminaudit.Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Action)
	}
	return out
}

// TestApprove_HappyPath — PR-L2.3: 4-eyes approve flow. Creator →
// pending, другой admin → approve → active. Emits
// apply_hold_approved event.
func TestApprove_HappyPath(t *testing.T) {
	h, repo, rec := setupHandler(t)
	ctx := context.Background()
	seeded, _ := h.svc.CreateHold(ctx, "u-target", "case", "r", "u-creator")

	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/approve", nil), "u-approver")
	req = mux.SetURLVars(req, map[string]string{"id": seeded.ID})
	w := httptest.NewRecorder()
	h.Approve(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if repo.holds[0].Status != StatusActive || !repo.holds[0].IsActive {
		t.Errorf("hold state after approve = %+v", repo.holds[0])
	}
	if repo.holds[0].ApprovedBy == nil || *repo.holds[0].ApprovedBy != "u-approver" {
		t.Errorf("approved_by = %v, want u-approver", repo.holds[0].ApprovedBy)
	}
	actions := actionsFromEvents(rec.events)
	if len(actions) != 1 || actions[0] != "apply_hold_approved" {
		t.Errorf("actions = %v, want [apply_hold_approved]", actions)
	}
	if !rec.events[0].Success {
		t.Error("approve event success=false")
	}
	meta := rec.events[0].Metadata.(map[string]any)
	if meta["status"] != "active" {
		t.Errorf("metadata.status = %v, want active", meta["status"])
	}
}

// TestApprove_SelfApproval_Forbidden — 4-eyes enforcement на handler
// layer. creator == approver → 403 + metadata.error_code=self_approval.
// Критический тест для compliance-audit'а.
func TestApprove_SelfApproval_Forbidden(t *testing.T) {
	h, repo, rec := setupHandler(t)
	ctx := context.Background()
	seeded, _ := h.svc.CreateHold(ctx, "u-target", "case", "r", "u-admin")

	// Тот же admin пытается approve.
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/approve", nil), "u-admin")
	req = mux.SetURLVars(req, map[string]string{"id": seeded.ID})
	w := httptest.NewRecorder()
	h.Approve(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	// Hold остаётся pending.
	if repo.holds[0].Status != StatusPending {
		t.Errorf("hold status = %q, want pending (self-approval НЕ должен применяться)", repo.holds[0].Status)
	}
	if rec.events[0].Success {
		t.Error("self-approval event success=true, expected false")
	}
	meta := rec.events[0].Metadata.(map[string]any)
	if meta["error_code"] != "self_approval" {
		t.Errorf("error_code = %v, want self_approval (SIEM-alerting key)", meta["error_code"])
	}
}

// TestApprove_NotPending_Conflict — approve на уже active → 409.
func TestApprove_NotPending_Conflict(t *testing.T) {
	h, _, _ := setupHandler(t)
	ctx := context.Background()
	seeded, _ := h.svc.CreateHold(ctx, "u-target", "case", "r", "u-creator")
	_, _ = h.svc.Approve(ctx, seeded.ID, "u-approver1")

	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/approve", nil), "u-approver2")
	req = mux.SetURLVars(req, map[string]string{"id": seeded.ID})
	w := httptest.NewRecorder()
	h.Approve(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

// TestApprove_Handler_NotFound — несуществующий id → 404.
func TestApprove_Handler_NotFound(t *testing.T) {
	h, _, _ := setupHandler(t)
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/h-missing/approve", nil), "u-admin")
	req = mux.SetURLVars(req, map[string]string{"id": "h-missing"})
	w := httptest.NewRecorder()
	h.Approve(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// TestApprove_NonAdmin_Forbidden.
func TestApprove_NonAdmin(t *testing.T) {
	h, _, _ := setupHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/legal-holds/x/approve", nil)
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{UserID: "u-user", Role: auth.RoleUser}))
	req = mux.SetURLVars(req, map[string]string{"id": "x"})
	w := httptest.NewRecorder()
	h.Approve(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// TestReject_HappyPath — pending → released, rejector может быть
// creator'ом (это cancel, не approval).
func TestReject_HappyPath(t *testing.T) {
	h, repo, rec := setupHandler(t)
	ctx := context.Background()
	seeded, _ := h.svc.CreateHold(ctx, "u-target", "case", "r", "u-admin")

	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/reject", nil), "u-admin")
	req = mux.SetURLVars(req, map[string]string{"id": seeded.ID})
	w := httptest.NewRecorder()
	h.Reject(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if repo.holds[0].Status != StatusReleased {
		t.Errorf("hold status = %q, want released", repo.holds[0].Status)
	}
	actions := actionsFromEvents(rec.events)
	if len(actions) != 1 || actions[0] != "apply_hold_rejected" {
		t.Errorf("actions = %v, want [apply_hold_rejected]", actions)
	}
}

// TestReject_NotPending_Conflict — reject на active → 409 (release
// flow, не reject).
func TestReject_NotPending_Conflict(t *testing.T) {
	h, _, _ := setupHandler(t)
	ctx := context.Background()
	seeded, _ := h.svc.CreateHold(ctx, "u-target", "case", "r", "u-creator")
	_, _ = h.svc.Approve(ctx, seeded.ID, "u-approver")

	req := adminCtx(httptest.NewRequest(http.MethodPost, "/api/legal-holds/"+seeded.ID+"/reject", nil), "u-admin")
	req = mux.SetURLVars(req, map[string]string{"id": seeded.ID})
	w := httptest.NewRecorder()
	h.Reject(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

// TestPendingHold_DoesNotBlockDSAR — critical semantic guard: pending
// hold НЕ блокирует erasure (HasActiveHold возвращает false).
// Защищает от regression'а если status/is_active sync сломается.
func TestPendingHold_DoesNotBlockDSAR(t *testing.T) {
	h, _, _ := setupHandler(t)
	ctx := context.Background()
	_, _ = h.svc.CreateHold(ctx, "u-target", "case", "r", "u-admin")

	has, err := h.svc.HasActiveHold(ctx, "u-target")
	if err != nil {
		t.Fatalf("HasActiveHold: %v", err)
	}
	if has {
		t.Error("pending hold блокирует DSAR — L2.3 contract нарушен")
	}
}

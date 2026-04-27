package budget

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/domain"
)

type stubBudgetRepo struct {
	budget *domain.Budget
	upsert *domain.Budget
}

func (s *stubBudgetRepo) GetByUserID(_ context.Context, userID string) (*domain.Budget, error) {
	if s.budget != nil && s.budget.UserID == userID {
		return s.budget, nil
	}
	return nil, errBudgetNotFound{}
}

func (s *stubBudgetRepo) Upsert(_ context.Context, b *domain.Budget) error {
	cp := *b
	s.upsert = &cp
	return nil
}

func (s *stubBudgetRepo) UpdateSpent(_ context.Context, _ string, _ float64, _ int) error {
	return nil
}

type errBudgetNotFound struct{}

func (errBudgetNotFound) Error() string { return "not found" }

type stubBudgetUserLookup struct {
	byID map[string]*domain.User
}

func (s stubBudgetUserLookup) GetByID(_ context.Context, id string) (*domain.User, error) {
	if u := s.byID[id]; u != nil {
		return u, nil
	}
	return nil, errBudgetNotFound{}
}

func (s stubBudgetUserLookup) GetByIDScoped(_ context.Context, id, orgID string) (*domain.User, error) {
	if u := s.byID[id]; u != nil && u.OrgID == orgID {
		return u, nil
	}
	return nil, errBudgetNotFound{}
}

func budgetRequest(method, targetID, body string, claims *auth.Claims) *http.Request {
	req := httptest.NewRequest(method, "/api/budgets/"+targetID, strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"user_id": targetID})
	if claims != nil {
		req = req.WithContext(auth.WithClaims(req.Context(), claims))
	}
	return req
}

func TestBudgetUpdate_TenantAdmin_CrossOrgDenied(t *testing.T) {
	repo := &stubBudgetRepo{}
	h := NewHandler(NewService(repo, nil)).WithUserLookup(stubBudgetUserLookup{byID: map[string]*domain.User{
		"u-target": {ID: "u-target", OrgID: "org-b", IsActive: true},
	}})
	req := budgetRequest(http.MethodPut, "u-target", `{"monthly_limit_usd":50,"period_start":"`+time.Now().UTC().Format(time.RFC3339)+`"}`, &auth.Claims{
		UserID: "u-admin", Role: auth.RoleAdmin, OrgID: "org-a",
	})
	rec := httptest.NewRecorder()

	h.Update(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d, body=%s; want 404", rec.Code, rec.Body.String())
	}
	if repo.upsert != nil {
		t.Fatalf("budget upsert happened for cross-org target: %+v", repo.upsert)
	}
}

func TestBudgetUpdate_TenantAdmin_SameOrgAllowed(t *testing.T) {
	repo := &stubBudgetRepo{}
	h := NewHandler(NewService(repo, nil)).WithUserLookup(stubBudgetUserLookup{byID: map[string]*domain.User{
		"u-target": {ID: "u-target", OrgID: "org-a", IsActive: true},
	}})
	req := budgetRequest(http.MethodPut, "u-target", `{"monthly_limit_usd":50,"period_start":"`+time.Now().UTC().Format(time.RFC3339)+`"}`, &auth.Claims{
		UserID: "u-admin", Role: auth.RoleAdmin, OrgID: "org-a",
	})
	rec := httptest.NewRecorder()

	h.Update(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, body=%s; want 200", rec.Code, rec.Body.String())
	}
	if repo.upsert == nil || repo.upsert.UserID != "u-target" {
		t.Fatalf("budget not upserted for same-org target: %+v", repo.upsert)
	}
}

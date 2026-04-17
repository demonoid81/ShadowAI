package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

// stubEraser — фейковая реализация Eraser-интерфейса.
// Принимает заданный результат/ошибку и запоминает полученные args.
type stubEraser struct {
	result          *ErasureResult
	err             error
	lastActor       string
	lastTarget      string
	callCount       int
}

func (s *stubEraser) EraseUser(_ context.Context, actor, target string) (*ErasureResult, error) {
	s.callCount++
	s.lastActor = actor
	s.lastTarget = target
	return s.result, s.err
}

// requestWithClaims — helper создаёт POST /users/{id}/erase
// с проставленными claims (через context).
func requestWithClaims(targetID string, claims *Claims) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/users/"+targetID+"/erase", nil)
	req = mux.SetURLVars(req, map[string]string{"id": targetID})
	if claims != nil {
		req = req.WithContext(WithClaims(req.Context(), claims))
	}
	return req
}

// TestEraseUser_Completed — happy path: admin → 200 + completed + counters.
func TestEraseUser_Completed(t *testing.T) {
	eraser := &stubEraser{result: &ErasureResult{
		UserID: "u-target", Status: ErasureCompleted,
		AuditRowsScrubbed: 42, BudgetsDeleted: 1,
	}}
	h := NewHandler(nil, eraser)

	req := requestWithClaims("u-target", &Claims{UserID: "u-admin", Role: RoleAdmin})
	rec := httptest.NewRecorder()
	h.EraseUser(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, body=%s", rec.Code, rec.Body.String())
	}
	var body ErasureResult
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != ErasureCompleted {
		t.Errorf("status=%q, want completed", body.Status)
	}
	if body.AuditRowsScrubbed != 42 || body.BudgetsDeleted != 1 {
		t.Errorf("counters mismatch: %+v", body)
	}
	if eraser.lastActor != "u-admin" || eraser.lastTarget != "u-target" {
		t.Errorf("eraser args: actor=%q target=%q", eraser.lastActor, eraser.lastTarget)
	}
}

// TestEraseUser_AlreadyErased — идемпотентность: status 200 + already_erased,
// без counters (omitempty).
func TestEraseUser_AlreadyErased(t *testing.T) {
	eraser := &stubEraser{result: &ErasureResult{
		UserID: "u-target", Status: ErasureAlreadyErased,
	}}
	h := NewHandler(nil, eraser)

	req := requestWithClaims("u-target", &Claims{UserID: "u-admin", Role: RoleAdmin})
	rec := httptest.NewRecorder()
	h.EraseUser(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}
	if !contains(rec.Body.String(), `"status":"already_erased"`) {
		t.Errorf("body doesn't contain already_erased: %s", rec.Body.String())
	}
}

// TestEraseUser_NotFound — не существует и не был erased → 404.
func TestEraseUser_NotFound(t *testing.T) {
	eraser := &stubEraser{result: &ErasureResult{
		UserID: "u-unknown", Status: ErasureNotFound,
	}}
	h := NewHandler(nil, eraser)

	req := requestWithClaims("u-unknown", &Claims{UserID: "u-admin", Role: RoleAdmin})
	rec := httptest.NewRecorder()
	h.EraseUser(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status=%d, want 404", rec.Code)
	}
}

// TestEraseUser_NonAdmin_403 — не-admin получает 403, eraser НЕ вызван.
func TestEraseUser_NonAdmin_403(t *testing.T) {
	eraser := &stubEraser{}
	h := NewHandler(nil, eraser)

	req := requestWithClaims("u-target", &Claims{UserID: "u-user", Role: RoleUser})
	rec := httptest.NewRecorder()
	h.EraseUser(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status=%d, want 403", rec.Code)
	}
	if eraser.callCount != 0 {
		t.Error("non-admin не должен был вызвать eraser")
	}
}

// TestEraseUser_Unauthenticated_401 — без claims → 401.
func TestEraseUser_Unauthenticated_401(t *testing.T) {
	eraser := &stubEraser{}
	h := NewHandler(nil, eraser)

	req := requestWithClaims("u-target", nil)
	rec := httptest.NewRecorder()
	h.EraseUser(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401", rec.Code)
	}
}

// TestEraseUser_EraserUnconfigured_503 — если eraser=nil, endpoint
// возвращает 503 (feature не включена), не 500 (runtime error).
func TestEraseUser_EraserUnconfigured_503(t *testing.T) {
	h := NewHandler(nil, nil)

	req := requestWithClaims("u-target", &Claims{UserID: "u-admin", Role: RoleAdmin})
	rec := httptest.NewRecorder()
	h.EraseUser(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status=%d, want 503 (eraser не сконфигурирован)", rec.Code)
	}
}

// TestEraseUser_EraserReturnsError_500 — runtime-ошибка eraser → 500.
// Detail не утекает (общий message "erasure failed").
func TestEraseUser_EraserReturnsError_500(t *testing.T) {
	eraser := &stubEraser{err: errors.New("database on fire")}
	h := NewHandler(nil, eraser)

	req := requestWithClaims("u-target", &Claims{UserID: "u-admin", Role: RoleAdmin})
	rec := httptest.NewRecorder()
	h.EraseUser(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status=%d, want 500", rec.Code)
	}
	if contains(rec.Body.String(), "database on fire") {
		t.Error("internal error details leaked в response")
	}
}

// TestEraseUser_MissingID_400 — пустой {id} в URL → 400.
func TestEraseUser_MissingID_400(t *testing.T) {
	eraser := &stubEraser{}
	h := NewHandler(nil, eraser)

	// mux.Vars не проставлены — handler получит пустой id.
	req := httptest.NewRequest(http.MethodPost, "/users//erase", nil)
	req = req.WithContext(WithClaims(req.Context(), &Claims{UserID: "u-admin", Role: RoleAdmin}))

	rec := httptest.NewRecorder()
	h.EraseUser(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
}

// contains — мелкий helper для текстовых проверок (без strings import).
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

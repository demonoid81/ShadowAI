//go:build enterprise

package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// stubHoldChecker — минимальный HoldChecker для unit-теста ErasureService.
type stubHoldChecker struct {
	hasHold bool
	err     error
}

func (s *stubHoldChecker) HasActiveHold(_ context.Context, _ string) (bool, error) {
	return s.hasHold, s.err
}

// TestErasureService_WithHoldChecker_BlocksOnActiveHold — core unit
// test: когда hold present, EraseUser должен вернуть ErasureHoldActive
// ДО открытия транзакции (значит db может быть nil в тесте).
func TestErasureService_WithHoldChecker_BlocksOnActiveHold(t *testing.T) {
	svc := &ErasureService{
		db:          nil, // tx не создаётся при active hold
		holdChecker: &stubHoldChecker{hasHold: true},
	}
	res, err := svc.EraseUser(context.Background(), "u-admin", "u-target")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res == nil || res.Status != ErasureHoldActive {
		t.Errorf("res = %+v, want status=hold_active", res)
	}
	if res.UserID != "u-target" {
		t.Errorf("res.UserID = %q, want u-target", res.UserID)
	}
}

// TestErasureService_WithHoldChecker_ErrorIsFailClosed — checker
// возвращает error → EraseUser возвращает error (caller handler
// отдаст 500, а не выполнит erase).
func TestErasureService_WithHoldChecker_ErrorIsFailClosed(t *testing.T) {
	boom := errors.New("legal_holds table missing")
	svc := &ErasureService{
		db:          nil,
		holdChecker: &stubHoldChecker{err: boom},
	}
	_, err := svc.EraseUser(context.Background(), "u-admin", "u-target")
	if err == nil {
		t.Fatal("expected error on hold checker failure")
	}
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want wrap of %v", err, boom)
	}
}

// TestErasureService_NoHoldChecker_ProceedsAsUsual — legacy path
// (nil checker) пропускает hold-check. Мы проверяем, что без
// hold'а логика идёт в db.BeginTx, который упадёт с nil-pointer.
// Ошибка в фазе tx doesn't mean нашей логики, а — ожидаемая
// реакция на nil *sql.DB. Значит hold-check точно пропустили.
func TestErasureService_NoHoldChecker_ProceedsAsUsual(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic from nil *sql.DB — proof что hold-check пропущен")
		}
	}()
	svc := &ErasureService{db: nil, holdChecker: nil}
	_, _ = svc.EraseUser(context.Background(), "u-admin", "u-target")
}

// TestWithHoldChecker_Chainable — fluent setter возвращает тот же
// pointer, удобно для wire-кода.
func TestWithHoldChecker_Chainable(t *testing.T) {
	orig := NewErasureService(nil, nil, nil)
	chained := orig.WithHoldChecker(&stubHoldChecker{})
	if chained != orig {
		t.Error("WithHoldChecker returned different pointer")
	}
	if orig.holdChecker == nil {
		t.Error("holdChecker not set on original service")
	}
}

// Silences "imported and not used: database/sql" if test removes
// other references.
var _ = sql.ErrNoRows

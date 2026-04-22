//go:build enterprise

package legalhold

import (
	"context"
	"errors"
	"testing"
	"time"
)

// memRepo — in-memory Repository для service-tests.
type memRepo struct {
	holds   []Hold
	nextID  int
	failOn  string // "create"/"release"/"list"/"has" — искусственная ошибка
	failErr error
}

func (m *memRepo) Create(_ context.Context, h *Hold) (*Hold, error) {
	if m.failOn == "create" {
		return nil, m.failErr
	}
	for _, ex := range m.holds {
		if ex.TargetUserID == h.TargetUserID && ex.IsActive {
			return nil, ErrAlreadyActive
		}
	}
	m.nextID++
	h.ID = "h-" + itoa(m.nextID)
	h.CreatedAt = time.Now().UTC()
	h.IsActive = true
	m.holds = append(m.holds, *h)
	return h, nil
}

func (m *memRepo) Release(_ context.Context, id, releasedBy string) (*Hold, error) {
	if m.failOn == "release" {
		return nil, m.failErr
	}
	for i := range m.holds {
		if m.holds[i].ID == id {
			if !m.holds[i].IsActive {
				return nil, ErrNotActive
			}
			now := time.Now().UTC()
			m.holds[i].IsActive = false
			m.holds[i].ReleasedAt = &now
			if releasedBy != "" {
				s := releasedBy
				m.holds[i].ReleasedBy = &s
			}
			h := m.holds[i]
			return &h, nil
		}
	}
	return nil, ErrNotFound
}

func (m *memRepo) HasActiveHold(_ context.Context, userID string) (bool, error) {
	if m.failOn == "has" {
		return false, m.failErr
	}
	for _, h := range m.holds {
		if h.TargetUserID == userID && h.IsActive {
			return true, nil
		}
	}
	return false, nil
}

func (m *memRepo) List(_ context.Context) ([]Hold, error) {
	if m.failOn == "list" {
		return nil, m.failErr
	}
	// Copy для изоляции.
	out := make([]Hold, len(m.holds))
	copy(out, m.holds)
	return out, nil
}

func (m *memRepo) ActiveUserIDs(_ context.Context) ([]string, error) {
	if m.failOn == "active" {
		return nil, m.failErr
	}
	var ids []string
	for _, h := range m.holds {
		if h.IsActive {
			ids = append(ids, h.TargetUserID)
		}
	}
	return ids, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestCreateHold_Happy — базовый flow.
func TestCreateHold_Happy(t *testing.T) {
	s := NewService(&memRepo{})
	h, err := s.CreateHold(context.Background(), "u-1", "case-42", "litigation XYZ", "u-admin")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h.TargetUserID != "u-1" || h.CaseRef != "case-42" || !h.IsActive {
		t.Errorf("hold shape: %+v", h)
	}
	if h.CreatedBy == nil || *h.CreatedBy != "u-admin" {
		t.Errorf("created_by = %v", h.CreatedBy)
	}
}

// TestCreateHold_MissingFields — case_ref/reason обязательны.
func TestCreateHold_MissingFields(t *testing.T) {
	s := NewService(&memRepo{})
	cases := []struct{ user, cref, reason string }{
		{"", "case", "reason"},
		{"u-1", "", "reason"},
		{"u-1", "case", ""},
		{"u-1", "   ", "reason"}, // whitespace-only trimmed
	}
	for _, c := range cases {
		if _, err := s.CreateHold(context.Background(), c.user, c.cref, c.reason, "u-admin"); err == nil {
			t.Errorf("expected error for %+v", c)
		}
	}
}

// TestCreateHold_DuplicateActive — second active hold на того же
// user'а → ErrAlreadyActive.
func TestCreateHold_DuplicateActive(t *testing.T) {
	s := NewService(&memRepo{})
	_, _ = s.CreateHold(context.Background(), "u-1", "case-1", "reason", "u-admin")
	_, err := s.CreateHold(context.Background(), "u-1", "case-2", "reason", "u-admin")
	if !IsAlreadyActive(err) {
		t.Errorf("err = %v, want ErrAlreadyActive", err)
	}
}

// TestCreateHold_AllowsAfterRelease — released hold не блокирует
// новый apply.
func TestCreateHold_AllowsAfterRelease(t *testing.T) {
	s := NewService(&memRepo{})
	h1, _ := s.CreateHold(context.Background(), "u-1", "case-1", "r1", "u-admin")
	if _, err := s.ReleaseHold(context.Background(), h1.ID, "u-admin"); err != nil {
		t.Fatalf("release: %v", err)
	}
	h2, err := s.CreateHold(context.Background(), "u-1", "case-2", "r2", "u-admin")
	if err != nil {
		t.Fatalf("second create after release: %v", err)
	}
	if !h2.IsActive {
		t.Error("second hold not active")
	}
}

// TestReleaseHold_Happy — release flow, second release → ErrNotActive.
func TestReleaseHold_Happy(t *testing.T) {
	s := NewService(&memRepo{})
	h, _ := s.CreateHold(context.Background(), "u-1", "case", "r", "u-admin")

	released, err := s.ReleaseHold(context.Background(), h.ID, "u-admin")
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if released.IsActive {
		t.Error("hold still active after release")
	}
	if released.ReleasedAt == nil {
		t.Error("released_at not set")
	}

	// Idempotent: second release → ErrNotActive.
	if _, err := s.ReleaseHold(context.Background(), h.ID, "u-admin"); !IsNotActive(err) {
		t.Errorf("second release err = %v, want ErrNotActive", err)
	}
}

// TestReleaseHold_NotFound — несуществующий ID.
func TestReleaseHold_NotFound(t *testing.T) {
	s := NewService(&memRepo{})
	_, err := s.ReleaseHold(context.Background(), "h-missing", "u-admin")
	if !IsNotFound(err) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// TestHasActiveHold_ActiveAndReleased — активный hold возвращает true;
// released — false.
func TestHasActiveHold_ActiveAndReleased(t *testing.T) {
	s := NewService(&memRepo{})
	has, _ := s.HasActiveHold(context.Background(), "u-1")
	if has {
		t.Error("fresh user: expected no hold")
	}
	h, _ := s.CreateHold(context.Background(), "u-1", "case", "r", "u-admin")
	has, _ = s.HasActiveHold(context.Background(), "u-1")
	if !has {
		t.Error("expected active hold after create")
	}
	_, _ = s.ReleaseHold(context.Background(), h.ID, "u-admin")
	has, _ = s.HasActiveHold(context.Background(), "u-1")
	if has {
		t.Error("released hold should not block")
	}
}

// TestHasActiveHold_RepoError_FailClosed — repo возвращает error.
// Service НЕ маскирует её; caller (ErasureService) должен обрабатывать
// как fail-closed.
func TestHasActiveHold_RepoError(t *testing.T) {
	boom := errors.New("db down")
	s := NewService(&memRepo{failOn: "has", failErr: boom})
	_, err := s.HasActiveHold(context.Background(), "u-1")
	if err == nil || !errors.Is(err, boom) {
		t.Errorf("err = %v, want to wrap %v", err, boom)
	}
}

// TestHasActiveHold_NilService_FailClosed — nil Service → (true, err).
// Защищает ErasureService от случайного wire с nil checker'ом.
func TestHasActiveHold_NilService_FailClosed(t *testing.T) {
	var s *Service
	has, err := s.HasActiveHold(context.Background(), "u-1")
	if !has {
		t.Error("nil service: has=false, want fail-closed true")
	}
	if err == nil {
		t.Error("nil service: err=nil, want err")
	}
}

// TestActiveUserIDs_HappyPath — PR-L2: scheduler получает только
// active-hold target_user_ids.
func TestActiveUserIDs_HappyPath(t *testing.T) {
	s := NewService(&memRepo{})
	ctx := context.Background()
	h1, _ := s.CreateHold(ctx, "u-active-1", "c1", "r", "u-admin")
	_, _ = s.CreateHold(ctx, "u-active-2", "c2", "r", "u-admin")
	h3, _ := s.CreateHold(ctx, "u-released", "c3", "r", "u-admin")
	_ = h1
	// Release third hold.
	_, _ = s.ReleaseHold(ctx, h3.ID, "u-admin")

	ids, err := s.ActiveUserIDs(ctx)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// 2 active, released исключён.
	if len(ids) != 2 {
		t.Errorf("ids = %v, want 2 active", ids)
	}
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	if !set["u-active-1"] || !set["u-active-2"] {
		t.Errorf("expected u-active-1 and u-active-2 in %v", ids)
	}
	if set["u-released"] {
		t.Error("released hold's user_id leaked в active list")
	}
}

// TestActiveUserIDs_Empty — чистый deploy без holds.
func TestActiveUserIDs_Empty(t *testing.T) {
	s := NewService(&memRepo{})
	ids, err := s.ActiveUserIDs(context.Background())
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("ids = %v, want empty", ids)
	}
}

// TestActiveUserIDs_NilService_FailClosed — fail-closed для
// scheduler: если service не сконфигурирован, scheduler не
// должен делать unrestricted purge.
func TestActiveUserIDs_NilService_FailClosed(t *testing.T) {
	var s *Service
	_, err := s.ActiveUserIDs(context.Background())
	if err == nil {
		t.Error("nil service: err=nil, want err (fail-closed)")
	}
}

// TestList_Ordering — active first, released после. Пока repo
// сохраняет insertion order, проверяем что List возвращает всё
// и IsActive flag корректен.
func TestList_IncludesAll(t *testing.T) {
	s := NewService(&memRepo{})
	h1, _ := s.CreateHold(context.Background(), "u-1", "c1", "r", "u-admin")
	_, _ = s.CreateHold(context.Background(), "u-2", "c2", "r", "u-admin")
	_, _ = s.ReleaseHold(context.Background(), h1.ID, "u-admin")

	list, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("list len = %d, want 2", len(list))
	}
	var activeSeen, releasedSeen bool
	for _, h := range list {
		if h.IsActive {
			activeSeen = true
		} else {
			releasedSeen = true
		}
	}
	if !activeSeen || !releasedSeen {
		t.Errorf("expected both active and released in list, got active=%v released=%v", activeSeen, releasedSeen)
	}
}

//go:build enterprise

package legalhold

import (
	"context"
	"errors"
	"testing"
	"time"
)

// memRepo — in-memory Repository для service-tests.
//
// PR-L2.3: обновлён под 4-eyes workflow.
//   - Create ставит Status=pending, IsActive=false.
//   - Approve: pending → active, проверка approver != creator.
//   - Reject: pending → released.
//   - Release: active → released.
//   - HasActiveHold/ActiveUserIDs проверяют ИМЕННО Status=active
//     (pending не блокирует DSAR / не защищает от purge).
//   - "Blocking hold" для уникальности = pending OR active
//     (partial-unique index в миграции 015).
type memRepo struct {
	holds   []Hold
	nextID  int
	failOn  string // "create"/"release"/"list"/"has"/"active"/"approve"/"reject"
	failErr error
}

func (m *memRepo) Create(_ context.Context, h *Hold) (*Hold, error) {
	if m.failOn == "create" {
		return nil, m.failErr
	}
	// Blocking check: один pending ИЛИ active per user (матчит
	// partial-unique index idx_legal_holds_blocking_per_user).
	for _, ex := range m.holds {
		if ex.TargetUserID == h.TargetUserID &&
			(ex.Status == StatusPending || ex.Status == StatusActive) {
			return nil, ErrAlreadyActive
		}
	}
	m.nextID++
	h.ID = "h-" + itoa(m.nextID)
	h.CreatedAt = time.Now().UTC()
	h.Status = StatusPending
	h.IsActive = false
	m.holds = append(m.holds, *h)
	return h, nil
}

func (m *memRepo) Approve(_ context.Context, id, approverID string) (*Hold, error) {
	if m.failOn == "approve" {
		return nil, m.failErr
	}
	for i := range m.holds {
		if m.holds[i].ID != id {
			continue
		}
		if m.holds[i].Status != StatusPending {
			return nil, ErrNotPending
		}
		// 4-eyes policy: approver != creator.
		if m.holds[i].CreatedBy != nil && *m.holds[i].CreatedBy == approverID {
			return nil, ErrSelfApproval
		}
		now := time.Now().UTC()
		m.holds[i].Status = StatusActive
		m.holds[i].IsActive = true
		m.holds[i].ApprovedAt = &now
		ap := approverID
		m.holds[i].ApprovedBy = &ap
		h := m.holds[i]
		return &h, nil
	}
	return nil, ErrNotFound
}

func (m *memRepo) Reject(_ context.Context, id, rejectorID string) (*Hold, error) {
	if m.failOn == "reject" {
		return nil, m.failErr
	}
	for i := range m.holds {
		if m.holds[i].ID != id {
			continue
		}
		if m.holds[i].Status != StatusPending {
			return nil, ErrNotPending
		}
		now := time.Now().UTC()
		m.holds[i].Status = StatusReleased
		m.holds[i].IsActive = false
		m.holds[i].ReleasedAt = &now
		if rejectorID != "" {
			s := rejectorID
			m.holds[i].ReleasedBy = &s
		}
		h := m.holds[i]
		return &h, nil
	}
	return nil, ErrNotFound
}

func (m *memRepo) Release(_ context.Context, id, releasedBy string) (*Hold, error) {
	if m.failOn == "release" {
		return nil, m.failErr
	}
	for i := range m.holds {
		if m.holds[i].ID == id {
			if m.holds[i].Status != StatusActive {
				return nil, ErrNotActive
			}
			now := time.Now().UTC()
			m.holds[i].Status = StatusReleased
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
		if h.TargetUserID == userID && h.Status == StatusActive {
			return true, nil
		}
	}
	return false, nil
}

func (m *memRepo) List(_ context.Context) ([]Hold, error) {
	if m.failOn == "list" {
		return nil, m.failErr
	}
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
		if h.Status == StatusActive {
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

// approveAs — helper для тестов: создать + approve другим admin'ом.
// Позволяет писать сценарии "hold is active" компактно.
func approveAs(t *testing.T, s *Service, h *Hold, approver string) *Hold {
	t.Helper()
	approved, err := s.Approve(context.Background(), h.ID, approver)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	return approved
}

// TestCreateHold_CreatesPending — PR-L2.3: create возвращает
// pending, НЕ active. Hold ещё не блокирует DSAR / не защищает
// от purge.
func TestCreateHold_CreatesPending(t *testing.T) {
	s := NewService(&memRepo{})
	h, err := s.CreateHold(context.Background(), "u-1", "case-42", "litigation XYZ", "u-admin")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h.Status != StatusPending {
		t.Errorf("status = %q, want pending", h.Status)
	}
	if h.IsActive {
		t.Error("IsActive=true на fresh create; expected false (pending)")
	}
	if h.TargetUserID != "u-1" || h.CaseRef != "case-42" {
		t.Errorf("hold shape: %+v", h)
	}
	if h.CreatedBy == nil || *h.CreatedBy != "u-admin" {
		t.Errorf("created_by = %v", h.CreatedBy)
	}

	// pending hold НЕ должен блокировать DSAR / purge:
	has, err := s.HasActiveHold(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("HasActiveHold err: %v", err)
	}
	if has {
		t.Error("pending hold блокирует DSAR — это нарушает L2.3 semantics")
	}
}

// TestCreateHold_MissingFields — case_ref/reason/user обязательны.
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

// TestCreateHold_DuplicateBlocking — второй hold на того же user'а
// (в pending ИЛИ active) → ErrAlreadyActive. Под L2.3 index покрывает
// оба статуса, чтобы admin не мог создать второй pending поверх
// существующего.
func TestCreateHold_DuplicateBlocking(t *testing.T) {
	s := NewService(&memRepo{})
	// Сначала pending vs pending.
	_, _ = s.CreateHold(context.Background(), "u-1", "case-1", "reason", "u-admin")
	_, err := s.CreateHold(context.Background(), "u-1", "case-2", "reason", "u-admin")
	if !IsAlreadyActive(err) {
		t.Errorf("pending+pending: err = %v, want ErrAlreadyActive", err)
	}

	// Теперь active vs pending: approve'нутый hold тоже блокирует.
	s2 := NewService(&memRepo{})
	h1, _ := s2.CreateHold(context.Background(), "u-2", "case-1", "reason", "u-admin")
	_ = approveAs(t, s2, h1, "u-approver")
	_, err = s2.CreateHold(context.Background(), "u-2", "case-2", "reason", "u-admin")
	if !IsAlreadyActive(err) {
		t.Errorf("active+pending: err = %v, want ErrAlreadyActive", err)
	}
}

// TestCreateHold_AllowsAfterReleased — released hold не блокирует
// новый apply (ни pending, ни subsequent approve).
func TestCreateHold_AllowsAfterReleased(t *testing.T) {
	s := NewService(&memRepo{})
	h1, _ := s.CreateHold(context.Background(), "u-1", "case-1", "r1", "u-admin")
	_ = approveAs(t, s, h1, "u-approver")
	if _, err := s.ReleaseHold(context.Background(), h1.ID, "u-admin"); err != nil {
		t.Fatalf("release: %v", err)
	}
	h2, err := s.CreateHold(context.Background(), "u-1", "case-2", "r2", "u-admin")
	if err != nil {
		t.Fatalf("second create after release: %v", err)
	}
	if h2.Status != StatusPending {
		t.Errorf("second hold status = %q, want pending", h2.Status)
	}
}

// TestCreateHold_AllowsAfterRejected — отклонённый pending hold
// тоже освобождает user'а для нового apply.
func TestCreateHold_AllowsAfterRejected(t *testing.T) {
	s := NewService(&memRepo{})
	h1, _ := s.CreateHold(context.Background(), "u-1", "case-1", "r1", "u-admin")
	if _, err := s.Reject(context.Background(), h1.ID, "u-admin"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if _, err := s.CreateHold(context.Background(), "u-1", "case-2", "r2", "u-admin"); err != nil {
		t.Fatalf("create after reject: %v", err)
	}
}

// TestApprove_Happy — pending → active, подставляются approved_at/by.
func TestApprove_Happy(t *testing.T) {
	s := NewService(&memRepo{})
	h, _ := s.CreateHold(context.Background(), "u-1", "case", "r", "u-creator")

	approved, err := s.Approve(context.Background(), h.ID, "u-approver")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if approved.Status != StatusActive {
		t.Errorf("status = %q, want active", approved.Status)
	}
	if !approved.IsActive {
		t.Error("IsActive=false after approve")
	}
	if approved.ApprovedAt == nil {
		t.Error("approved_at not set")
	}
	if approved.ApprovedBy == nil || *approved.ApprovedBy != "u-approver" {
		t.Errorf("approved_by = %v, want u-approver", approved.ApprovedBy)
	}

	// После approve hold блокирует DSAR.
	has, err := s.HasActiveHold(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("HasActiveHold: %v", err)
	}
	if !has {
		t.Error("approved hold не блокирует DSAR — contract нарушен")
	}
}

// TestApprove_SelfApproval_Blocked — 4-eyes policy: approver ==
// creator → ErrSelfApproval.
func TestApprove_SelfApproval_Blocked(t *testing.T) {
	s := NewService(&memRepo{})
	h, _ := s.CreateHold(context.Background(), "u-1", "case", "r", "u-admin")

	_, err := s.Approve(context.Background(), h.ID, "u-admin")
	if !IsSelfApproval(err) {
		t.Errorf("err = %v, want ErrSelfApproval", err)
	}

	// Hold остаётся pending.
	list, _ := s.List(context.Background())
	if list[0].Status != StatusPending {
		t.Errorf("status = %q after failed self-approval, want pending", list[0].Status)
	}
}

// TestApprove_NotPending — approve на active → ErrNotPending.
func TestApprove_NotPending(t *testing.T) {
	s := NewService(&memRepo{})
	h, _ := s.CreateHold(context.Background(), "u-1", "case", "r", "u-creator")
	_ = approveAs(t, s, h, "u-approver1")

	// Второй approve (even by another admin) → not pending.
	_, err := s.Approve(context.Background(), h.ID, "u-approver2")
	if !IsNotPending(err) {
		t.Errorf("err = %v, want ErrNotPending", err)
	}
}

// TestApprove_NotFound.
func TestApprove_NotFound(t *testing.T) {
	s := NewService(&memRepo{})
	_, err := s.Approve(context.Background(), "h-missing", "u-approver")
	if !IsNotFound(err) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// TestApprove_Validation — пустой id/approver → validation.
func TestApprove_Validation(t *testing.T) {
	s := NewService(&memRepo{})
	if _, err := s.Approve(context.Background(), "", "u-approver"); !IsValidation(err) {
		t.Errorf("empty id: err = %v, want validation", err)
	}
	if _, err := s.Approve(context.Background(), "h-1", ""); !IsValidation(err) {
		t.Errorf("empty approver: err = %v, want validation", err)
	}
}

// TestReject_Happy — pending → released, ReleasedBy = rejector.
func TestReject_Happy(t *testing.T) {
	s := NewService(&memRepo{})
	h, _ := s.CreateHold(context.Background(), "u-1", "case", "r", "u-admin")

	rejected, err := s.Reject(context.Background(), h.ID, "u-admin")
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rejected.Status != StatusReleased {
		t.Errorf("status = %q, want released", rejected.Status)
	}
	if rejected.IsActive {
		t.Error("IsActive=true after reject")
	}
	if rejected.ReleasedAt == nil {
		t.Error("released_at not set")
	}
}

// TestReject_NotPending — reject на active → ErrNotPending (releases
// должны идти через Release, а не Reject).
func TestReject_NotPending(t *testing.T) {
	s := NewService(&memRepo{})
	h, _ := s.CreateHold(context.Background(), "u-1", "case", "r", "u-creator")
	_ = approveAs(t, s, h, "u-approver")

	_, err := s.Reject(context.Background(), h.ID, "u-admin")
	if !IsNotPending(err) {
		t.Errorf("err = %v, want ErrNotPending", err)
	}
}

// TestReject_AllowsSelfRejection — rejector может быть = creator
// (это cancellation собственного request'а, НЕ approval).
func TestReject_AllowsSelfRejection(t *testing.T) {
	s := NewService(&memRepo{})
	h, _ := s.CreateHold(context.Background(), "u-1", "case", "r", "u-admin")
	if _, err := s.Reject(context.Background(), h.ID, "u-admin"); err != nil {
		t.Fatalf("self-reject should be allowed: %v", err)
	}
}

// TestReleaseHold_OnlyActive — release на pending → ErrNotActive.
// Pending-hold'ы должны отменяться через Reject.
func TestReleaseHold_OnlyActive(t *testing.T) {
	s := NewService(&memRepo{})
	h, _ := s.CreateHold(context.Background(), "u-1", "case", "r", "u-admin")

	_, err := s.ReleaseHold(context.Background(), h.ID, "u-admin")
	if !IsNotActive(err) {
		t.Errorf("release(pending): err = %v, want ErrNotActive", err)
	}
}

// TestReleaseHold_AfterApprove — полный flow: create → approve →
// release.
func TestReleaseHold_AfterApprove(t *testing.T) {
	s := NewService(&memRepo{})
	h, _ := s.CreateHold(context.Background(), "u-1", "case", "r", "u-creator")
	_ = approveAs(t, s, h, "u-approver")

	released, err := s.ReleaseHold(context.Background(), h.ID, "u-releaser")
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if released.Status != StatusReleased {
		t.Errorf("status = %q, want released", released.Status)
	}

	// Idempotent: second release → ErrNotActive.
	if _, err := s.ReleaseHold(context.Background(), h.ID, "u-releaser"); !IsNotActive(err) {
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

// TestHasActiveHold_LifecyclePendingActiveReleased — PR-L2.3: только
// active блокирует. Pending и released — не блокируют.
func TestHasActiveHold_LifecyclePendingActiveReleased(t *testing.T) {
	s := NewService(&memRepo{})
	ctx := context.Background()

	// Fresh user — нет hold.
	if has, _ := s.HasActiveHold(ctx, "u-1"); has {
		t.Error("fresh user: expected no hold")
	}

	// Create pending — НЕ должен блокировать.
	h, _ := s.CreateHold(ctx, "u-1", "case", "r", "u-creator")
	if has, _ := s.HasActiveHold(ctx, "u-1"); has {
		t.Error("pending hold блокирует DSAR — contract нарушен")
	}

	// Approve — теперь блокирует.
	_ = approveAs(t, s, h, "u-approver")
	if has, _ := s.HasActiveHold(ctx, "u-1"); !has {
		t.Error("active hold должен блокировать, but doesn't")
	}

	// Release — больше не блокирует.
	_, _ = s.ReleaseHold(ctx, h.ID, "u-admin")
	if has, _ := s.HasActiveHold(ctx, "u-1"); has {
		t.Error("released hold всё ещё блокирует")
	}
}

// TestHasActiveHold_RepoError — repo error prop'ается, caller
// (ErasureService) интерпретирует как fail-closed.
func TestHasActiveHold_RepoError(t *testing.T) {
	boom := errors.New("db down")
	s := NewService(&memRepo{failOn: "has", failErr: boom})
	_, err := s.HasActiveHold(context.Background(), "u-1")
	if err == nil || !errors.Is(err, boom) {
		t.Errorf("err = %v, want to wrap %v", err, boom)
	}
}

// TestHasActiveHold_NilService_FailClosed — nil Service → (true, err).
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

// TestActiveUserIDs_OnlyActive — scheduler получает только
// active-hold target_user_ids; pending исключены.
func TestActiveUserIDs_OnlyActive(t *testing.T) {
	s := NewService(&memRepo{})
	ctx := context.Background()
	h1, _ := s.CreateHold(ctx, "u-active", "c1", "r", "u-creator")
	_ = approveAs(t, s, h1, "u-approver")
	// Pending hold (НЕ должен попасть в ActiveUserIDs).
	_, _ = s.CreateHold(ctx, "u-pending", "c2", "r", "u-creator")
	// Released hold (НЕ должен).
	h3, _ := s.CreateHold(ctx, "u-released", "c3", "r", "u-creator")
	_ = approveAs(t, s, h3, "u-approver")
	_, _ = s.ReleaseHold(ctx, h3.ID, "u-admin")
	// Rejected hold (НЕ должен).
	h4, _ := s.CreateHold(ctx, "u-rejected", "c4", "r", "u-creator")
	_, _ = s.Reject(ctx, h4.ID, "u-admin")

	ids, err := s.ActiveUserIDs(ctx)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	if !set["u-active"] {
		t.Errorf("expected u-active in %v", ids)
	}
	if set["u-pending"] {
		t.Error("pending leaked в ActiveUserIDs — защитный invariant нарушен")
	}
	if set["u-released"] {
		t.Error("released leaked в ActiveUserIDs")
	}
	if set["u-rejected"] {
		t.Error("rejected leaked в ActiveUserIDs")
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

// TestActiveUserIDs_NilService_FailClosed.
func TestActiveUserIDs_NilService_FailClosed(t *testing.T) {
	var s *Service
	_, err := s.ActiveUserIDs(context.Background())
	if err == nil {
		t.Error("nil service: err=nil, want err (fail-closed)")
	}
}

// TestList_AllStatusesVisible — List возвращает pending+active+released.
func TestList_AllStatusesVisible(t *testing.T) {
	s := NewService(&memRepo{})
	ctx := context.Background()
	h1, _ := s.CreateHold(ctx, "u-1", "c1", "r", "u-creator")
	_ = approveAs(t, s, h1, "u-approver")
	_, _ = s.CreateHold(ctx, "u-2", "c2", "r", "u-creator") // pending
	h3, _ := s.CreateHold(ctx, "u-3", "c3", "r", "u-creator")
	_ = approveAs(t, s, h3, "u-approver")
	_, _ = s.ReleaseHold(ctx, h3.ID, "u-admin")

	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("list len = %d, want 3", len(list))
	}
	statusCount := map[Status]int{}
	for _, h := range list {
		statusCount[h.Status]++
	}
	if statusCount[StatusActive] != 1 || statusCount[StatusPending] != 1 || statusCount[StatusReleased] != 1 {
		t.Errorf("status distribution: %v, want 1/1/1", statusCount)
	}
}

// TestService_NilRepo_AllMethods — защитный контракт: все методы
// на nil Service возвращают ErrNotConfigured, не panic.
func TestService_NilRepo_AllMethods(t *testing.T) {
	var s *Service
	ctx := context.Background()
	if _, err := s.CreateHold(ctx, "u", "c", "r", "a"); !IsNotConfigured(err) {
		t.Errorf("Create nil: %v", err)
	}
	if _, err := s.ReleaseHold(ctx, "id", "a"); !IsNotConfigured(err) {
		t.Errorf("Release nil: %v", err)
	}
	if _, err := s.Approve(ctx, "id", "a"); !IsNotConfigured(err) {
		t.Errorf("Approve nil: %v", err)
	}
	if _, err := s.Reject(ctx, "id", "a"); !IsNotConfigured(err) {
		t.Errorf("Reject nil: %v", err)
	}
	if _, err := s.List(ctx); !IsNotConfigured(err) {
		t.Errorf("List nil: %v", err)
	}
}

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

// Release — PR-L5: теперь RequestRelease (active → release_pending).
func (m *memRepo) Release(_ context.Context, id, requesterID string) (*Hold, error) {
	if m.failOn == "release" {
		return nil, m.failErr
	}
	for i := range m.holds {
		if m.holds[i].ID == id {
			switch m.holds[i].Status {
			case StatusPending:
				return nil, ErrPendingNotReleasable
			case StatusReleased:
				return nil, ErrNotActive
			case StatusReleasePending:
				return nil, ErrAlreadyReleasePending
			case StatusActive:
				// ok
			default:
				return nil, ErrNotActive
			}
			now := time.Now().UTC()
			m.holds[i].Status = StatusReleasePending
			m.holds[i].ReleaseRequestedAt = &now
			if requesterID != "" {
				s := requesterID
				m.holds[i].ReleaseRequestedBy = &s
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
		// PR-L5: blocks for active AND release_pending.
		if h.TargetUserID == userID && (h.Status == StatusActive || h.Status == StatusReleasePending) {
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
		// PR-L5: includes release_pending.
		if h.Status == StatusActive || h.Status == StatusReleasePending {
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

func (m *memRepo) ApproveRelease(_ context.Context, id, approverID string) (*Hold, error) {
	for i := range m.holds {
		if m.holds[i].ID != id {
			continue
		}
		if m.holds[i].Status != StatusReleasePending {
			return nil, ErrNotReleasePending
		}
		// 4-eyes: approver != release requester.
		if m.holds[i].ReleaseRequestedBy != nil && *m.holds[i].ReleaseRequestedBy == approverID {
			return nil, ErrSelfReleaseApproval
		}
		now := time.Now().UTC()
		m.holds[i].Status = StatusReleased
		m.holds[i].IsActive = false
		m.holds[i].ReleasedAt = &now
		if approverID != "" {
			s := approverID
			m.holds[i].ReleasedBy = &s
		}
		h := m.holds[i]
		return &h, nil
	}
	return nil, ErrNotFound
}

func (m *memRepo) RejectRelease(_ context.Context, id, rejectorID string) (*Hold, error) {
	for i := range m.holds {
		if m.holds[i].ID != id {
			continue
		}
		if m.holds[i].Status != StatusReleasePending {
			return nil, ErrNotReleasePending
		}
		m.holds[i].Status = StatusActive
		m.holds[i].IsActive = true
		m.holds[i].ReleaseRequestedAt = nil
		m.holds[i].ReleaseRequestedBy = nil
		_ = rejectorID
		h := m.holds[i]
		return &h, nil
	}
	return nil, ErrNotFound
}

func (m *memRepo) PendingOlderThan(_ context.Context, threshold time.Duration) ([]Hold, error) {
	cutoff := time.Now().UTC().Add(-threshold)
	var out []Hold
	for _, h := range m.holds {
		if h.Status == StatusPending && h.CreatedAt.Before(cutoff) {
			out = append(out, h)
		}
	}
	return out, nil
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

// TestReleaseHold_PendingUseReject — PR-L2.3 regression guard:
// Release на pending возвращает ErrPendingNotReleasable (distinct
// from ErrNotActive), чтобы handler мог вернуть 409 вместо ошибочного
// 200 already_released. Operator должен использовать /reject для
// отмены pending.
func TestReleaseHold_PendingUseReject(t *testing.T) {
	s := NewService(&memRepo{})
	h, _ := s.CreateHold(context.Background(), "u-1", "case", "r", "u-admin")

	_, err := s.ReleaseHold(context.Background(), h.ID, "u-admin")
	if !IsPendingNotReleasable(err) {
		t.Errorf("release(pending): err = %v, want ErrPendingNotReleasable", err)
	}
	// Критично: НЕ должен collapse'ить в ErrNotActive (иначе
	// handler трактует как идемпотентный 200 already_released).
	if IsNotActive(err) {
		t.Error("pending release collapsed в ErrNotActive — handler ложно вернёт 200")
	}
}

// TestReleaseHold_AfterApprove — PR-L5: полный flow: create → approve →
// release (request_release) → approve_release → released.
func TestReleaseHold_AfterApprove(t *testing.T) {
	s := NewService(&memRepo{})
	h, _ := s.CreateHold(context.Background(), "u-1", "case", "r", "u-creator")
	_ = approveAs(t, s, h, "u-approver")

	// Step 1: ReleaseHold → release_pending (не immediate release).
	pending, err := s.ReleaseHold(context.Background(), h.ID, "u-releaser")
	if err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}
	if pending.Status != StatusReleasePending {
		t.Errorf("status after ReleaseHold = %q, want release_pending", pending.Status)
	}

	// Повторный ReleaseHold → ErrAlreadyReleasePending (не ErrNotActive).
	if _, err := s.ReleaseHold(context.Background(), h.ID, "u-releaser2"); !IsAlreadyReleasePending(err) {
		t.Errorf("second ReleaseHold err = %v, want ErrAlreadyReleasePending", err)
	}

	// Step 2: ApproveRelease другим admin → released.
	released, err := s.ApproveRelease(context.Background(), h.ID, "u-approver2")
	if err != nil {
		t.Fatalf("ApproveRelease: %v", err)
	}
	if released.Status != StatusReleased {
		t.Errorf("status after ApproveRelease = %q, want released", released.Status)
	}

	// После ApproveRelease: третий ReleaseHold → ErrNotActive (идемпотентно).
	if _, err := s.ReleaseHold(context.Background(), h.ID, "u-releaser"); !IsNotActive(err) {
		t.Errorf("release of released hold err = %v, want ErrNotActive", err)
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

// TestHasActiveHold_LifecyclePendingActiveReleased — PR-L5: lifecycle:
// pending (не блокирует) → active (блокирует) → release_pending
// (всё ещё блокирует) → released (не блокирует).
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

	// ReleaseHold → release_pending: DSAR всё ещё заблокирован (PR-L5).
	_, _ = s.ReleaseHold(ctx, h.ID, "u-admin")
	if has, _ := s.HasActiveHold(ctx, "u-1"); !has {
		t.Error("release_pending hold должен блокировать DSAR — PR-L5 contract нарушен")
	}

	// ApproveRelease → released: теперь больше не блокирует.
	_, _ = s.ApproveRelease(ctx, h.ID, "u-admin2")
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

// TestActiveUserIDs_OnlyActive — PR-L5: scheduler получает
// active И release_pending target_user_ids; pending и released
// (полностью) исключены.
func TestActiveUserIDs_OnlyActive(t *testing.T) {
	s := NewService(&memRepo{})
	ctx := context.Background()
	h1, _ := s.CreateHold(ctx, "u-active", "c1", "r", "u-creator")
	_ = approveAs(t, s, h1, "u-approver")
	// Pending hold (НЕ должен попасть в ActiveUserIDs).
	_, _ = s.CreateHold(ctx, "u-pending", "c2", "r", "u-creator")
	// Fully released hold (НЕ должен): нужен полный release-cycle
	// (ReleaseHold + ApproveRelease) чтобы выйти из active.
	h3, _ := s.CreateHold(ctx, "u-released", "c3", "r", "u-creator")
	_ = approveAs(t, s, h3, "u-approver")
	_, _ = s.ReleaseHold(ctx, h3.ID, "u-admin-req")
	_, _ = s.ApproveRelease(ctx, h3.ID, "u-admin-approver")
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
		t.Error("fully released leaked в ActiveUserIDs")
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

// TestList_AllStatusesVisible — PR-L5: List возвращает
// pending+active+released. Для получения released нужен полный
// release-cycle (ReleaseHold + ApproveRelease).
func TestList_AllStatusesVisible(t *testing.T) {
	s := NewService(&memRepo{})
	ctx := context.Background()
	h1, _ := s.CreateHold(ctx, "u-1", "c1", "r", "u-creator")
	_ = approveAs(t, s, h1, "u-approver")
	_, _ = s.CreateHold(ctx, "u-2", "c2", "r", "u-creator") // pending
	h3, _ := s.CreateHold(ctx, "u-3", "c3", "r", "u-creator")
	_ = approveAs(t, s, h3, "u-approver")
	// Полный release-cycle: ReleaseHold (→ release_pending) + ApproveRelease (→ released).
	_, _ = s.ReleaseHold(ctx, h3.ID, "u-admin-req")
	_, _ = s.ApproveRelease(ctx, h3.ID, "u-admin-approver")

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
		t.Errorf("status distribution: %v, want 1/1/1 (active/pending/released)", statusCount)
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

// ---------------------------------------------------------------------------
// PR-L5: Release 4-eyes, DSAR blocking, Bulk, SLA tests
// ---------------------------------------------------------------------------

// activateHold — helper: create + approve to reach active state.
func activateHold(t *testing.T, s *Service, userID string) *Hold {
	t.Helper()
	h, err := s.CreateHold(context.Background(), userID, "case-l5", "litigation L5", "admin-creator")
	if err != nil {
		t.Fatalf("CreateHold: %v", err)
	}
	return approveAs(t, s, h, "admin-approver")
}

// TestL5_Release_SelfApproval_Denied — DoD: approver of release must
// differ from release requester (4-eyes for release).
func TestL5_Release_SelfApproval_Denied(t *testing.T) {
	s := NewService(&memRepo{})
	h := activateHold(t, s, "u-release-self")

	// Request release as "admin-requester".
	rp, err := s.ReleaseHold(context.Background(), h.ID, "admin-requester")
	if err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}
	if rp.Status != StatusReleasePending {
		t.Fatalf("status after ReleaseHold = %s, want release_pending", rp.Status)
	}

	// Attempt to self-approve (same actor "admin-requester").
	_, err = s.ApproveRelease(context.Background(), h.ID, "admin-requester")
	if !IsSelfReleaseApproval(err) {
		t.Errorf("self release approval: want ErrSelfReleaseApproval, got %v", err)
	}
}

// TestL5_ReleasePending_StillBlocksDSAR — DoD: DSAR must be blocked for
// release_pending holds.
func TestL5_ReleasePending_StillBlocksDSAR(t *testing.T) {
	s := NewService(&memRepo{})
	h := activateHold(t, s, "u-release-pending-dsar")

	// Request release → release_pending.
	if _, err := s.ReleaseHold(context.Background(), h.ID, "admin-req"); err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}

	// DSAR check must still return true (hold still legally blocking).
	blocked, err := s.HasActiveHold(context.Background(), "u-release-pending-dsar")
	if err != nil {
		t.Fatalf("HasActiveHold: %v", err)
	}
	if !blocked {
		t.Error("release_pending: HasActiveHold should return true (DSAR still blocked)")
	}
}

// TestL5_ApproveRelease_UnblocksDSAR — DoD: after ApproveRelease, DSAR
// is no longer blocked.
func TestL5_ApproveRelease_UnblocksDSAR(t *testing.T) {
	s := NewService(&memRepo{})
	h := activateHold(t, s, "u-approve-release")

	if _, err := s.ReleaseHold(context.Background(), h.ID, "admin-req"); err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}

	// Approve by different admin.
	released, err := s.ApproveRelease(context.Background(), h.ID, "admin-approver-2")
	if err != nil {
		t.Fatalf("ApproveRelease: %v", err)
	}
	if released.Status != StatusReleased {
		t.Errorf("ApproveRelease: status = %s, want released", released.Status)
	}

	// DSAR check must now return false.
	blocked, err := s.HasActiveHold(context.Background(), "u-approve-release")
	if err != nil {
		t.Fatalf("HasActiveHold: %v", err)
	}
	if blocked {
		t.Error("after ApproveRelease: HasActiveHold should return false (DSAR unblocked)")
	}
}

// TestL5_RejectRelease_KeepsBlock — DoD: after RejectRelease, hold
// returns to active and DSAR remains blocked.
func TestL5_RejectRelease_KeepsBlock(t *testing.T) {
	s := NewService(&memRepo{})
	h := activateHold(t, s, "u-reject-release")

	if _, err := s.ReleaseHold(context.Background(), h.ID, "admin-req"); err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}

	// Reject release.
	restored, err := s.RejectRelease(context.Background(), h.ID, "admin-rejector")
	if err != nil {
		t.Fatalf("RejectRelease: %v", err)
	}
	if restored.Status != StatusActive {
		t.Errorf("RejectRelease: status = %s, want active", restored.Status)
	}

	// DSAR check must still return true.
	blocked, err := s.HasActiveHold(context.Background(), "u-reject-release")
	if err != nil {
		t.Fatalf("HasActiveHold: %v", err)
	}
	if !blocked {
		t.Error("after RejectRelease: HasActiveHold should return true (back to active)")
	}
}

// TestL5_Bulk_PartialFailure — DoD: bulk partial failure is reported
// per-item; other items are not rolled back.
func TestL5_BulkApprove_PartialFailure(t *testing.T) {
	s := NewService(&memRepo{})

	// Create two pending holds.
	h1, _ := s.CreateHold(context.Background(), "u-bulk-1", "case-b1", "reason", "creator-bulk")
	h2, _ := s.CreateHold(context.Background(), "u-bulk-2", "case-b2", "reason", "creator-bulk")

	// Approve first hold normally; leave second as pending.
	// Now bulk approve: h1 will fail (already approved by approver-1 != creator),
	// h2 will succeed, h3 doesn't exist → fail.
	h1ap, _ := s.Approve(context.Background(), h1.ID, "approver-1") // h1 is now active
	_ = h1ap

	// Bulk approve [h1, h2, "nonexistent"] as "approver-2".
	// h1: already active → ErrNotPending
	// h2: pending → active (success, approver-2 != creator-bulk)
	// nonexistent: ErrNotFound
	results, err := s.BulkApprove(context.Background(),
		[]string{h1.ID, h2.ID, "nonexistent"}, "approver-2")
	if err != nil {
		t.Fatalf("BulkApprove: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("BulkApprove: expected 3 results, got %d", len(results))
	}

	// h1: fail (not_pending)
	if results[0].Success {
		t.Errorf("h1 (already active) should fail, got success")
	}
	if results[0].Error != "not_pending" {
		t.Errorf("h1 error_code = %q, want not_pending", results[0].Error)
	}

	// h2: success
	if !results[1].Success {
		t.Errorf("h2 should succeed, got error: %s", results[1].Error)
	}
	if results[1].Status != StatusActive {
		t.Errorf("h2 status = %s, want active", results[1].Status)
	}

	// nonexistent: fail (not_found)
	if results[2].Success {
		t.Errorf("nonexistent should fail")
	}
	if results[2].Error != "not_found" {
		t.Errorf("nonexistent error_code = %q, want not_found", results[2].Error)
	}
}

// TestL5_SLA_PendingQuery — DoD: PendingOlderThan returns pending holds
// older than threshold.
func TestL5_SLA_PendingQuery(t *testing.T) {
	repo := &memRepo{}
	s := NewService(repo)
	ctx := context.Background()

	// Create a hold and backdated it in the repo.
	h, _ := s.CreateHold(ctx, "u-sla", "case-sla", "sla test", "creator-sla")

	// Backdate the created_at to simulate an old pending hold.
	for i := range repo.holds {
		if repo.holds[i].ID == h.ID {
			repo.holds[i].CreatedAt = time.Now().UTC().Add(-50 * time.Hour)
		}
	}

	// Query with 24h threshold: should return the backdated hold.
	holds, err := s.PendingOlderThan(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("PendingOlderThan: %v", err)
	}
	if len(holds) != 1 || holds[0].ID != h.ID {
		t.Errorf("PendingOlderThan(24h): expected 1 hold, got %d", len(holds))
	}

	// Query with 72h threshold: should NOT return it (only 50h old).
	holds2, _ := s.PendingOlderThan(ctx, 72*time.Hour)
	if len(holds2) != 0 {
		t.Errorf("PendingOlderThan(72h): expected 0 holds, got %d", len(holds2))
	}
}

// TestL5_WholeUserBackwardCompat — DoD: existing whole_user holds
// continue to work after L5 scope model addition.
func TestL5_WholeUserBackwardCompat(t *testing.T) {
	s := NewService(&memRepo{})
	h, err := s.CreateHold(context.Background(), "u-compat", "case-compat", "backward compat", "creator")
	if err != nil {
		t.Fatalf("CreateHold: %v", err)
	}
	if h.Status != StatusPending {
		t.Errorf("new hold status = %s, want pending", h.Status)
	}
	// Scope type defaults to whole_user in memRepo (not set explicitly).
	// The Hold struct has ScopeType field; memRepo doesn't set it = default.
	// Legacy whole_user behavior: DSAR/purge protection on active holds.
	approved := approveAs(t, s, h, "approver-compat")
	if approved.Status != StatusActive {
		t.Errorf("approved status = %s, want active", approved.Status)
	}
	blocked, _ := s.HasActiveHold(context.Background(), "u-compat")
	if !blocked {
		t.Error("whole_user backward compat: active hold should block DSAR")
	}
}

// TestL5_AlreadyReleasePending_IsConflict — повторный RequestRelease
// возвращает явный конфликт, не idempotent.
func TestL5_AlreadyReleasePending_IsConflict(t *testing.T) {
	s := NewService(&memRepo{})
	h := activateHold(t, s, "u-double-release")

	if _, err := s.ReleaseHold(context.Background(), h.ID, "admin-req"); err != nil {
		t.Fatalf("first ReleaseHold: %v", err)
	}
	// Second RequestRelease: must fail with ErrAlreadyReleasePending.
	_, err := s.ReleaseHold(context.Background(), h.ID, "admin-req2")
	if !IsAlreadyReleasePending(err) {
		t.Errorf("second ReleaseHold: want ErrAlreadyReleasePending, got %v", err)
	}
}

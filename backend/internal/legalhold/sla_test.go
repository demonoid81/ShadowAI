//go:build enterprise

package legalhold

import (
	"context"
	"testing"
	"time"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/domain"
)

type slaRepo struct {
	holds   []Hold
	signals map[string]bool
}

func (r *slaRepo) Create(context.Context, *Hold) (*Hold, error) { panic("unused") }
func (r *slaRepo) Release(context.Context, string, string) (*Hold, error) {
	panic("unused")
}
func (r *slaRepo) HasActiveHold(context.Context, string) (bool, error) { panic("unused") }
func (r *slaRepo) List(context.Context) ([]Hold, error)                { panic("unused") }
func (r *slaRepo) ActiveUserIDs(context.Context) ([]string, error)     { panic("unused") }
func (r *slaRepo) Approve(context.Context, string, string) (*Hold, error) {
	panic("unused")
}
func (r *slaRepo) Reject(context.Context, string, string) (*Hold, error) {
	panic("unused")
}
func (r *slaRepo) ApproveRelease(context.Context, string, string) (*Hold, error) {
	panic("unused")
}
func (r *slaRepo) RejectRelease(context.Context, string, string) (*Hold, error) {
	panic("unused")
}
func (r *slaRepo) PendingOlderThan(context.Context, time.Duration) ([]Hold, error) {
	panic("unused")
}

func (r *slaRepo) HoldsOlderThanStatus(_ context.Context, status Status, cutoff time.Time) ([]Hold, error) {
	out := make([]Hold, 0)
	for _, h := range r.holds {
		switch status {
		case StatusPending:
			if h.Status == status && h.CreatedAt.Before(cutoff) {
				out = append(out, h)
			}
		case StatusReleasePending:
			if h.Status == status && h.ReleaseRequestedAt != nil && h.ReleaseRequestedAt.Before(cutoff) {
				out = append(out, h)
			}
		}
	}
	return out, nil
}

func (r *slaRepo) SLASignalExists(_ context.Context, holdID string, status Status, bucket string) (bool, error) {
	return r.signals[slaSignalKey(holdID, status, bucket)], nil
}

type slaRecorder struct {
	events []adminaudit.Event
	repo   *slaRepo
}

func (r *slaRecorder) Record(_ context.Context, ev adminaudit.Event) {
	r.events = append(r.events, ev)
	meta, _ := ev.Metadata.(map[string]any)
	holdID, _ := meta["hold_id"].(string)
	status, _ := meta["status"].(string)
	bucket, _ := meta["dedupe_bucket"].(string)
	if r.repo != nil && holdID != "" && status != "" && bucket != "" {
		r.repo.signals[slaSignalKey(holdID, Status(status), bucket)] = true
	}
}

func TestEmitSLASignals_PendingBreachEmitsOnce(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	repo := &slaRepo{
		signals: map[string]bool{},
		holds: []Hold{{
			ID:           "hold-pending",
			OrgID:        domain.DefaultOrgID,
			TargetUserID: "user-1",
			Status:       StatusPending,
			CreatedAt:    now.Add(-25 * time.Hour),
		}},
	}
	rec := &slaRecorder{repo: repo}

	report, err := NewService(repo).EmitSLASignals(context.Background(), rec, SLAConfig{
		PendingThreshold:        24 * time.Hour,
		ReleasePendingThreshold: 24 * time.Hour,
		Now:                     now,
	})
	if err != nil {
		t.Fatalf("EmitSLASignals: %v", err)
	}
	if report.PendingEmitted != 1 || len(rec.events) != 1 {
		t.Fatalf("report=%+v events=%d, want one pending emission", report, len(rec.events))
	}
	ev := rec.events[0]
	if ev.Action != "legal_hold_sla_breached" || ev.Resource != "legal_hold" || ev.TargetID != "hold-pending" {
		t.Fatalf("event mismatch: %+v", ev)
	}
	meta := ev.Metadata.(map[string]any)
	if meta["event_code"] != "legal_hold_pending_sla_breached" {
		t.Fatalf("event_code=%v", meta["event_code"])
	}

	report, err = NewService(repo).EmitSLASignals(context.Background(), rec, SLAConfig{
		PendingThreshold:        24 * time.Hour,
		ReleasePendingThreshold: 24 * time.Hour,
		Now:                     now,
	})
	if err != nil {
		t.Fatalf("second EmitSLASignals: %v", err)
	}
	if report.DuplicatesSkipped != 1 || len(rec.events) != 1 {
		t.Fatalf("duplicate scan report=%+v events=%d, want skipped duplicate", report, len(rec.events))
	}
}

func TestEmitSLASignals_ReleasePendingUsesReleaseRequestAge(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	oldRelease := now.Add(-49 * time.Hour)
	recentRelease := now.Add(-2 * time.Hour)
	repo := &slaRepo{
		signals: map[string]bool{},
		holds: []Hold{
			{
				ID:                 "hold-old-release",
				OrgID:              domain.DefaultOrgID,
				Status:             StatusReleasePending,
				CreatedAt:          now.Add(-200 * time.Hour),
				ReleaseRequestedAt: &oldRelease,
			},
			{
				ID:                 "hold-recent-release",
				OrgID:              domain.DefaultOrgID,
				Status:             StatusReleasePending,
				CreatedAt:          now.Add(-200 * time.Hour),
				ReleaseRequestedAt: &recentRelease,
			},
		},
	}
	rec := &slaRecorder{repo: repo}

	report, err := NewService(repo).EmitSLASignals(context.Background(), rec, SLAConfig{
		PendingThreshold:        24 * time.Hour,
		ReleasePendingThreshold: 24 * time.Hour,
		Now:                     now,
	})
	if err != nil {
		t.Fatalf("EmitSLASignals: %v", err)
	}
	if report.ReleasePendingEmitted != 1 || len(rec.events) != 1 {
		t.Fatalf("report=%+v events=%d, want one release_pending emission", report, len(rec.events))
	}
	meta := rec.events[0].Metadata.(map[string]any)
	if meta["event_code"] != "legal_hold_release_pending_sla_breached" {
		t.Fatalf("event_code=%v", meta["event_code"])
	}
	if rec.events[0].TargetID != "hold-old-release" {
		t.Fatalf("target=%q, want hold-old-release", rec.events[0].TargetID)
	}
}

func TestEmitSLASignals_NoBreachIgnored(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	repo := &slaRepo{
		signals: map[string]bool{},
		holds: []Hold{{
			ID:        "hold-new",
			OrgID:     domain.DefaultOrgID,
			Status:    StatusPending,
			CreatedAt: now.Add(-2 * time.Hour),
		}},
	}
	rec := &slaRecorder{repo: repo}

	report, err := NewService(repo).EmitSLASignals(context.Background(), rec, SLAConfig{
		PendingThreshold:        24 * time.Hour,
		ReleasePendingThreshold: 24 * time.Hour,
		Now:                     now,
	})
	if err != nil {
		t.Fatalf("EmitSLASignals: %v", err)
	}
	if report.PendingEmitted != 0 || report.ReleasePendingEmitted != 0 || len(rec.events) != 0 {
		t.Fatalf("report=%+v events=%d, want no emission", report, len(rec.events))
	}
}

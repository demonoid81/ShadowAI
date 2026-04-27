//go:build enterprise

package legalhold

import (
	"context"
	"fmt"
	"time"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/metrics"
)

const (
	ActionLegalHoldSLABreached = "legal_hold_sla_breached"
	EventLegalHoldPendingSLA   = "legal_hold_pending_sla_breached"
	EventLegalHoldReleaseSLA   = "legal_hold_release_pending_sla_breached"
)

type SLAConfig struct {
	PendingThreshold        time.Duration
	ReleasePendingThreshold time.Duration
	Now                     time.Time
}

type SLAReport struct {
	PendingCandidates        int
	ReleasePendingCandidates int
	PendingEmitted           int
	ReleasePendingEmitted    int
	DuplicatesSkipped        int
}

type SLAMonitorRepository interface {
	HoldsOlderThanStatus(ctx context.Context, status Status, cutoff time.Time) ([]Hold, error)
	SLASignalExists(ctx context.Context, holdID string, status Status, bucket string) (bool, error)
}

func (s *Service) EmitSLASignals(ctx context.Context, recorder adminaudit.Recorder, cfg SLAConfig) (SLAReport, error) {
	var report SLAReport
	if s == nil || s.repo == nil {
		return report, ErrNotConfigured
	}
	if cfg.PendingThreshold <= 0 || cfg.ReleasePendingThreshold <= 0 {
		return report, fmt.Errorf("sla thresholds must be positive: %w", ErrValidation)
	}
	if cfg.Now.IsZero() {
		cfg.Now = time.Now().UTC()
	} else {
		cfg.Now = cfg.Now.UTC()
	}
	repo, ok := s.repo.(SLAMonitorRepository)
	if !ok {
		return report, fmt.Errorf("legalhold: repo does not support SLA monitor")
	}
	pending, err := s.emitSLAForStatus(ctx, recorder, repo, StatusPending, cfg.PendingThreshold, cfg.Now)
	if err != nil {
		return report, err
	}
	releasePending, err := s.emitSLAForStatus(ctx, recorder, repo, StatusReleasePending, cfg.ReleasePendingThreshold, cfg.Now)
	if err != nil {
		return report, err
	}
	report.PendingCandidates = pending.candidates
	report.PendingEmitted = pending.emitted
	report.ReleasePendingCandidates = releasePending.candidates
	report.ReleasePendingEmitted = releasePending.emitted
	report.DuplicatesSkipped = pending.duplicates + releasePending.duplicates
	return report, nil
}

type slaStatusReport struct {
	candidates int
	emitted    int
	duplicates int
}

func (s *Service) emitSLAForStatus(ctx context.Context, recorder adminaudit.Recorder, repo SLAMonitorRepository, status Status, threshold time.Duration, now time.Time) (slaStatusReport, error) {
	var report slaStatusReport
	holds, err := repo.HoldsOlderThanStatus(ctx, status, now.Add(-threshold))
	if err != nil {
		return report, fmt.Errorf("legalhold: sla scan %s: %w", status, err)
	}
	report.candidates = len(holds)
	oldest := oldestSLAHours(holds, status, now)
	metrics.SetLegalHoldSLAOldestAge(string(status), oldest)
	bucket := slaBucket(now)
	for _, hold := range holds {
		exists, err := repo.SLASignalExists(ctx, hold.ID, status, bucket)
		if err != nil {
			return report, fmt.Errorf("legalhold: sla dedupe %s: %w", hold.ID, err)
		}
		if exists {
			report.duplicates++
			continue
		}
		if recorder != nil {
			recorder.Record(ctx, adminaudit.Event{
				ActorUserID: nil,
				Action:      ActionLegalHoldSLABreached,
				Resource:    "legal_hold",
				TargetID:    hold.ID,
				Path:        "scheduler",
				Method:      "INTERNAL",
				StatusCode:  200,
				Success:     false,
				OrgID:       orgOrDefault(hold.OrgID),
				TargetOrgID: orgOrDefault(hold.OrgID),
				Metadata: map[string]any{
					"event_code":      slaEventCode(status),
					"hold_id":         hold.ID,
					"status":          string(status),
					"age_hours":       int(now.Sub(slaAgeStart(hold, status)).Hours()),
					"threshold_hours": int(threshold.Hours()),
					"dedupe_bucket":   bucket,
				},
			})
		}
		metrics.RecordLegalHoldSLABreach(string(status))
		report.emitted++
	}
	return report, nil
}

func oldestSLAHours(holds []Hold, status Status, now time.Time) float64 {
	var oldest float64
	for _, h := range holds {
		age := now.Sub(slaAgeStart(h, status)).Hours()
		if age > oldest {
			oldest = age
		}
	}
	return oldest
}

func slaAgeStart(h Hold, status Status) time.Time {
	if status == StatusReleasePending && h.ReleaseRequestedAt != nil {
		return h.ReleaseRequestedAt.UTC()
	}
	return h.CreatedAt.UTC()
}

func slaEventCode(status Status) string {
	if status == StatusReleasePending {
		return EventLegalHoldReleaseSLA
	}
	return EventLegalHoldPendingSLA
}

func slaBucket(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

func slaSignalKey(holdID string, status Status, bucket string) string {
	return holdID + "|" + string(status) + "|" + bucket
}

func orgOrDefault(orgID string) string {
	if orgID == "" {
		return domain.DefaultOrgID
	}
	return orgID
}

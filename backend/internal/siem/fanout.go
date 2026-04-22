//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package siem

import (
	"context"

	"github.com/shadowai/backend/internal/adminaudit"
)

// FanoutAdminRecorder satisfies adminaudit.Recorder, но внутри
// fan-out'ит на два receiver'а: (1) локальный PostgreSQL writer
// (adminaudit.Service) и (2) SIEM HTTP recorder.
//
// Правило: DB всегда вызывается первым (это source of truth); SIEM —
// best-effort, failures не влияют на DB insertion.
//
// Handler'ы получают *FanoutAdminRecorder как adminaudit.Recorder —
// никаких изменений в signatures не требуется.
type FanoutAdminRecorder struct {
	DB   adminaudit.Recorder // nil-safe (dev без admin-audit БД)
	SIEM Recorder            // nil-safe (SIEM_ENABLED=false)
}

// Record пишет event в оба sink'а. Безопасно вызывать на *FanoutAdminRecorder=nil
// (превращается в no-op — защита Go'шного method dispatch).
func (f *FanoutAdminRecorder) Record(ctx context.Context, ev adminaudit.Event) {
	if f == nil {
		return
	}
	if f.DB != nil {
		f.DB.Record(ctx, ev)
	}
	if f.SIEM != nil {
		f.SIEM.Record(ctx, FromAdminEvent(ev))
	}
}

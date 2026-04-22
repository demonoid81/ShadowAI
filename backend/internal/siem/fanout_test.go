//go:build enterprise

package siem

import (
	"context"
	"errors"
	"testing"

	"github.com/shadowai/backend/internal/adminaudit"
)

// captureDBRecorder — mock для adminaudit.Recorder (DB side).
type captureDBRecorder struct {
	events []adminaudit.Event
	fail   error
}

func (c *captureDBRecorder) Record(_ context.Context, ev adminaudit.Event) {
	if c.fail != nil {
		// DB write failure не бросается вверх (reality: adminaudit.Service
		// fail-opens sам), но отмечаем.
		return
	}
	c.events = append(c.events, ev)
}

// captureSIEMRecorder — mock для siem.Recorder.
type captureSIEMRecorder struct {
	events []Event
	fail   bool // если true — паникует; используем для проверки, что
	// fanout НЕ ловит панику SIEM'а (т.к. HTTP recorder сам fail-opens).
}

func (c *captureSIEMRecorder) Record(_ context.Context, ev Event) {
	if c.fail {
		panic("siem boom")
	}
	c.events = append(c.events, ev)
}

// TestFanout_BothRecordersCalled — happy path: оба sink'а получают
// event. DB получает raw adminaudit.Event; SIEM получает
// converted siem.Event.
func TestFanout_BothRecordersCalled(t *testing.T) {
	db := &captureDBRecorder{}
	siem := &captureSIEMRecorder{}
	f := &FanoutAdminRecorder{DB: db, SIEM: siem}

	actor := "u-admin"
	f.Record(context.Background(), adminaudit.Event{
		ActorUserID: &actor, Action: "read", Resource: "audit_logs",
		Path: "/api/audit/logs", Method: "GET", StatusCode: 200, Success: true,
	})

	if len(db.events) != 1 {
		t.Errorf("db events = %d, want 1", len(db.events))
	}
	if len(siem.events) != 1 {
		t.Errorf("siem events = %d, want 1", len(siem.events))
	}
	if db.events[0].Action != "read" {
		t.Errorf("db action = %q", db.events[0].Action)
	}
	if siem.events[0].Action != "read" {
		t.Errorf("siem action = %q", siem.events[0].Action)
	}
	if siem.events[0].CreatedAt == "" {
		t.Error("siem CreatedAt не заполнен")
	}
}

// TestFanout_NilSIEM_DBStillCalled — если SIEM не сконфигурирован,
// DB всё равно пишется. Симметрично — для dev без SIEM.
func TestFanout_NilSIEM_DBStillCalled(t *testing.T) {
	db := &captureDBRecorder{}
	f := &FanoutAdminRecorder{DB: db, SIEM: nil}

	f.Record(context.Background(), adminaudit.Event{Action: "x", Resource: "y"})
	if len(db.events) != 1 {
		t.Error("DB не получил event при nil SIEM")
	}
}

// TestFanout_NilDB_SIEMStillCalled — edge case (dev без
// admin_event_logs таблицы, но с SIEM): SIEM всё равно получает
// event. Крайний случай, но logically valid.
func TestFanout_NilDB_SIEMStillCalled(t *testing.T) {
	siem := &captureSIEMRecorder{}
	f := &FanoutAdminRecorder{DB: nil, SIEM: siem}

	f.Record(context.Background(), adminaudit.Event{Action: "x", Resource: "y"})
	if len(siem.events) != 1 {
		t.Error("SIEM не получил event при nil DB")
	}
}

// TestFanout_BothNil_Safe — полный nil bundle: Record не паникует.
func TestFanout_BothNil_Safe(t *testing.T) {
	f := &FanoutAdminRecorder{DB: nil, SIEM: nil}
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panic: %v", r)
		}
	}()
	f.Record(context.Background(), adminaudit.Event{Action: "x"})
}

// TestFanout_NilReceiver_Safe — *FanoutAdminRecorder=nil method call.
func TestFanout_NilReceiver_Safe(t *testing.T) {
	var f *FanoutAdminRecorder
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panic: %v", r)
		}
	}()
	f.Record(context.Background(), adminaudit.Event{Action: "x"})
}

// TestFanout_DBFirst_SIEMAfter — DB call порядок важен для
// consistency (если нам нужно гарантировать, что DB write завершён
// до SIEM write, например для idempotent replay). Проверяем порядок
// через sequence-checker.
func TestFanout_DBFirst_SIEMAfter(t *testing.T) {
	var seq []string
	db := &sequenceDBRecorder{seq: &seq}
	siem := &sequenceSIEMRecorder{seq: &seq}
	f := &FanoutAdminRecorder{DB: db, SIEM: siem}

	f.Record(context.Background(), adminaudit.Event{Action: "x"})
	if len(seq) != 2 || seq[0] != "db" || seq[1] != "siem" {
		t.Errorf("order = %v, want [db, siem]", seq)
	}
}

type sequenceDBRecorder struct{ seq *[]string }

func (s *sequenceDBRecorder) Record(_ context.Context, _ adminaudit.Event) {
	*s.seq = append(*s.seq, "db")
}

type sequenceSIEMRecorder struct{ seq *[]string }

func (s *sequenceSIEMRecorder) Record(_ context.Context, _ Event) {
	*s.seq = append(*s.seq, "siem")
}

// TestFromAdminEvent_PreservesFields — conversion Event-to-Event
// не теряет поля и не добавляет ничего лишнего.
func TestFromAdminEvent_PreservesFields(t *testing.T) {
	actor := "u-admin"
	in := adminaudit.Event{
		ActorUserID: &actor, Action: "update", Resource: "user",
		TargetID: "u-1", Path: "/x", Method: "PUT",
		StatusCode: 200, Success: true,
		Metadata: map[string]any{"k": "v"},
	}
	out := FromAdminEvent(in)
	if out.ActorUserID != in.ActorUserID ||
		out.Action != in.Action ||
		out.Resource != in.Resource ||
		out.TargetID != in.TargetID ||
		out.StatusCode != in.StatusCode ||
		out.Success != in.Success {
		t.Errorf("conversion потеряла поля: in=%+v out=%+v", in, out)
	}
	if out.CreatedAt == "" {
		t.Error("CreatedAt не заполнен")
	}
}

// Guard: unused err var в import.
var _ = errors.New

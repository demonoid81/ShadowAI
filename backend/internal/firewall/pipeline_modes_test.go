package firewall

import (
	"context"
	"testing"
)

// stubCallCountInspector — считает вызовы, чтобы верифицировать,
// что disabled-режим действительно пропускает инспектор.
type stubCallCountInspector struct {
	name      string
	reqCalls  int
	respCalls int
	decision  *Decision
}

func (s *stubCallCountInspector) Name() string { return s.name }
func (s *stubCallCountInspector) InspectRequest(_ context.Context, _ *Payload) (*Decision, error) {
	s.reqCalls++
	return s.decision, nil
}
func (s *stubCallCountInspector) InspectResponse(_ context.Context, _ *Payload) (*Decision, error) {
	s.respCalls++
	return s.decision, nil
}

// stubBlockingInspector всегда возвращает Block. Для enforce-режима должен
// останавливать chain, для shadow — только записывать наблюдение.
type stubBlockingInspector struct {
	name string
}

func (s *stubBlockingInspector) Name() string { return s.name }
func (s *stubBlockingInspector) InspectRequest(_ context.Context, _ *Payload) (*Decision, error) {
	return &Decision{
		Action:   ActionBlock,
		Reason:   "stub block",
		Severity: SeverityHigh,
		Findings: []Finding{{Type: "test", Severity: SeverityHigh, Match: "bad"}},
	}, nil
}
func (s *stubBlockingInspector) InspectResponse(_ context.Context, _ *Payload) (*Decision, error) {
	return &Decision{Action: ActionAllow}, nil
}

// TestPipeline_ShadowMode_DoesNotBlock — инспектор хочет Block, но в
// shadow-режиме итоговое решение для handler'а должно быть Allow, а
// shadow-наблюдение должно попасть в Decision.ShadowDecisions.
//
// Это корневое поведение shadow-режима: deploy inspector без риска
// аварийного blocking production traffic.
func TestPipeline_ShadowMode_DoesNotBlock(t *testing.T) {
	modes := NewInspectorModes(ModeEnforce)
	modes.Overrides["blocker"] = ModeShadow

	p := NewPipelineWithModes(modes)
	p.Register(&stubBlockingInspector{name: "blocker"})

	d, err := p.InspectRequest(context.Background(), &Payload{
		UserID: "u1", Text: "hello", Phase: PhaseRequest,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if d.Action != ActionAllow {
		t.Errorf("shadow-режим: Action = %q, want Allow (shadow не блокирует)", d.Action)
	}
	if len(d.ShadowDecisions) != 1 {
		t.Fatalf("ShadowDecisions len = %d, want 1", len(d.ShadowDecisions))
	}
	sd := d.ShadowDecisions[0]
	if sd.Inspector != "blocker" {
		t.Errorf("ShadowDecision.Inspector = %q, want blocker", sd.Inspector)
	}
	if sd.Action != ActionBlock {
		t.Errorf("ShadowDecision.Action = %q, want block (оригинальное решение)", sd.Action)
	}
	if sd.Severity != SeverityHigh {
		t.Errorf("ShadowDecision.Severity = %q, want high", sd.Severity)
	}
	if sd.Reason != "stub block" {
		t.Errorf("ShadowDecision.Reason = %q, want %q", sd.Reason, "stub block")
	}
}

// TestPipeline_ShadowMode_DoesNotMutateMetaFlagged — shadow ActionFlag
// НЕ должен выставлять Meta["flagged"]. Иначе downstream MultiTurn
// получит cross-inspector сигнал от инспектора, который в shadow-режиме
// не имеет права ничего сигналить в pipeline.
func TestPipeline_ShadowMode_DoesNotMutateMetaFlagged(t *testing.T) {
	modes := NewInspectorModes(ModeEnforce)
	modes.Overrides["shadow_flagger"] = ModeShadow

	p := NewPipelineWithModes(modes)
	p.Register(&stubFlaggingInspector{name: "shadow_flagger"})

	payload := &Payload{UserID: "u1", Text: "hi", Phase: PhaseRequest}
	if _, err := p.InspectRequest(context.Background(), payload); err != nil {
		t.Fatal(err)
	}

	if payload.Meta != nil && payload.Meta["flagged"] == "true" {
		t.Error("shadow ActionFlag не должен выставлять Meta[flagged]=true — " +
			"это превратило бы shadow в подстилку для активной логики")
	}
}

// TestPipeline_ShadowMode_DoesNotApplySanitize — shadow ActionSanitize
// НЕ должен применять SanitizedText к итоговому Decision.
// В противном случае shadow-инспектор мог бы тихо изменить запрос,
// отданный upstream.
func TestPipeline_ShadowMode_DoesNotApplySanitize(t *testing.T) {
	modes := NewInspectorModes(ModeEnforce)
	modes.Overrides["shadow_sanitizer"] = ModeShadow

	p := NewPipelineWithModes(modes)
	p.Register(&stubSanitizingInspector{name: "shadow_sanitizer"})

	d, err := p.InspectRequest(context.Background(), &Payload{
		UserID: "u1", Text: "hi", Phase: PhaseRequest,
	})
	if err != nil {
		t.Fatal(err)
	}

	if d.Action != ActionAllow {
		t.Errorf("shadow sanitize: финальное Action = %q, want Allow", d.Action)
	}
	if d.SanitizedText != "" {
		t.Errorf("shadow: SanitizedText = %q, want empty (shadow не применяется)", d.SanitizedText)
	}
	if len(d.ShadowDecisions) != 1 || d.ShadowDecisions[0].Action != ActionSanitize {
		t.Errorf("shadow sanitize должен попасть в ShadowDecisions[0], got %+v", d.ShadowDecisions)
	}
}

// TestPipeline_ShadowMode_AllowNotAppended — shadow Allow не должен
// попадать в ShadowDecisions: это шум (каждый запрос, где ничего не
// сработало, давал бы запись). Пишем только non-allow observations.
func TestPipeline_ShadowMode_AllowNotAppended(t *testing.T) {
	modes := NewInspectorModes(ModeEnforce)
	modes.Overrides["shadow_allower"] = ModeShadow

	p := NewPipelineWithModes(modes)
	p.Register(&stubAllowInspector{name: "shadow_allower"})

	d, err := p.InspectRequest(context.Background(), &Payload{UserID: "u1", Phase: PhaseRequest})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.ShadowDecisions) != 0 {
		t.Errorf("shadow Allow не должен писать в ShadowDecisions, got %+v", d.ShadowDecisions)
	}
}

// TestPipeline_DisabledMode_NotCalled — disabled-инспектор не должен
// вызываться вообще: ни InspectRequest, ни InspectResponse. Это контракт
// "инспектор выключен", позволяющий safely отключить неустойчивый
// инспектор без его удаления из кода.
func TestPipeline_DisabledMode_NotCalled(t *testing.T) {
	counter := &stubCallCountInspector{
		name:     "off",
		decision: &Decision{Action: ActionBlock, Reason: "should not run"},
	}

	modes := NewInspectorModes(ModeEnforce)
	modes.Overrides["off"] = ModeDisabled

	p := NewPipelineWithModes(modes)
	p.Register(counter)

	if _, err := p.InspectRequest(context.Background(), &Payload{Phase: PhaseRequest}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.InspectResponse(context.Background(), &Payload{Phase: PhaseResponse}); err != nil {
		t.Fatal(err)
	}

	if counter.reqCalls != 0 {
		t.Errorf("disabled inspector InspectRequest вызван %d раз, want 0", counter.reqCalls)
	}
	if counter.respCalls != 0 {
		t.Errorf("disabled inspector InspectResponse вызван %d раз, want 0", counter.respCalls)
	}
}

// TestPipeline_MixedModes_EnforceStillBlocks — enforce-инспектор всё ещё
// блокирует chain, даже если перед ним stoит shadow-инспектор.
// Порядок: shadow_observer → enforce_blocker → should_not_run.
// Ожидание: финальный Action=Block (от enforce), ShadowDecisions содержит
// наблюдение от shadow, should_not_run не вызван.
func TestPipeline_MixedModes_EnforceStillBlocks(t *testing.T) {
	modes := NewInspectorModes(ModeEnforce)
	modes.Overrides["shadow_observer"] = ModeShadow

	after := &stubCallCountInspector{
		name:     "should_not_run",
		decision: &Decision{Action: ActionAllow},
	}

	p := NewPipelineWithModes(modes)
	p.Register(&stubFlaggingInspector{name: "shadow_observer"})
	p.Register(&stubBlockingInspector{name: "enforce_blocker"})
	p.Register(after)

	d, err := p.InspectRequest(context.Background(), &Payload{Phase: PhaseRequest})
	if err != nil {
		t.Fatal(err)
	}

	if d.Action != ActionBlock {
		t.Errorf("mixed: Action = %q, want Block (enforce-инспектор всё равно блокирует)", d.Action)
	}
	if len(d.ShadowDecisions) != 1 {
		t.Errorf("mixed: ShadowDecisions len = %d, want 1 (от shadow_observer)", len(d.ShadowDecisions))
	}
	if after.reqCalls != 0 {
		t.Errorf("after-block inspector вызван %d раз, want 0 (Block должен остановить chain)", after.reqCalls)
	}
}

// TestPipeline_NewPipeline_DefaultEnforce — backward compat: старый
// конструктор NewPipeline() без modes → все инспекторы в enforce-mode.
// Это гарантирует, что существующие тесты и production-wiring не
// поменяют поведение.
func TestPipeline_NewPipeline_DefaultEnforce(t *testing.T) {
	p := NewPipeline()
	p.Register(&stubFlaggingInspector{name: "flagger"})

	payload := &Payload{UserID: "u1", Phase: PhaseRequest}
	d, err := p.InspectRequest(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	// В enforce-режиме ActionFlag мутирует Meta["flagged"] (PR-3 wire).
	if payload.Meta == nil || payload.Meta["flagged"] != "true" {
		t.Error("backward compat: NewPipeline() без modes должен работать как enforce " +
			"(Meta[flagged] должен мутироваться)")
	}
	if len(d.ShadowDecisions) != 0 {
		t.Errorf("enforce-режим не должен писать ShadowDecisions, got %+v", d.ShadowDecisions)
	}
}

// TestPipeline_ShadowMode_DoesNotCallRecordFlag — shadow ActionFlag
// НЕ должен вызывать ContentRateLimiter.RecordFlag(). Иначе shadow-
// инспектор тихо влиял бы на rate-limit state для реальных пользователей.
func TestPipeline_ShadowMode_DoesNotCallRecordFlag(t *testing.T) {
	rl := NewContentRateLimiter(ContentRateLimitConfig{
		Enabled:            true,
		MaxFlagsPerMinute:  2,
		MaxCharsPerMinute:  1_000_000,
	})

	modes := NewInspectorModes(ModeEnforce)
	modes.Overrides["shadow_flagger"] = ModeShadow

	p := NewPipelineWithModes(modes)
	p.Register(&stubFlaggingInspector{name: "shadow_flagger"})
	p.Register(rl)

	userID := "u-shadow-rl"
	// 5 раз подряд (> MaxFlagsPerMinute=2). Если shadow-flag вызывает
	// RecordFlag, rate-limiter начнёт возвращать Block после 3-го раза.
	for i := range 5 {
		d, err := p.InspectRequest(context.Background(), &Payload{
			UserID: userID, Text: "hi", Phase: PhaseRequest,
		})
		if err != nil {
			t.Fatal(err)
		}
		if d.Action == ActionBlock {
			t.Errorf("итерация %d: Action = Block — shadow ActionFlag не должен " +
				"накапливать RecordFlag state в ContentRateLimiter", i)
			return
		}
	}
}

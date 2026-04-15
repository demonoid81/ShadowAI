package firewall

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mockInspector struct {
	name            string
	requestDecision *Decision
	requestErr      error
	responseDecision *Decision
	responseErr     error
}

func (m *mockInspector) Name() string { return m.name }

func (m *mockInspector) InspectRequest(ctx context.Context, p *Payload) (*Decision, error) {
	return m.requestDecision, m.requestErr
}

func (m *mockInspector) InspectResponse(ctx context.Context, p *Payload) (*Decision, error) {
	return m.responseDecision, m.responseErr
}

func TestEmptyPipelineAllows(t *testing.T) {
	p := NewPipeline()
	d, err := p.InspectRequest(context.Background(), &Payload{Text: "hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionAllow {
		t.Errorf("expected allow, got %s", d.Action)
	}
	if d.Severity != SeverityLow {
		t.Errorf("expected low severity, got %s", d.Severity)
	}
}

func TestBlockStopsChain(t *testing.T) {
	p := NewPipeline()
	p.Register(&mockInspector{
		name: "blocker",
		requestDecision: &Decision{
			Action:   ActionBlock,
			Reason:   "blocked",
			Severity: SeverityHigh,
			Findings: []Finding{{Type: "test", Severity: SeverityHigh, Match: "bad"}},
		},
	})
	p.Register(&mockInspector{
		name: "should-not-run",
		requestDecision: &Decision{
			Action:   ActionAllow,
			Severity: SeverityLow,
			Findings: []Finding{{Type: "ok", Severity: SeverityLow, Match: "good"}},
		},
	})

	d, err := p.InspectRequest(context.Background(), &Payload{Text: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionBlock {
		t.Errorf("expected block, got %s", d.Action)
	}
	if d.InspectorName != "blocker" {
		t.Errorf("expected inspector name 'blocker', got %s", d.InspectorName)
	}
	if len(d.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(d.Findings))
	}
}

func TestAllowPassesThrough(t *testing.T) {
	p := NewPipeline()
	p.Register(&mockInspector{
		name: "allow1",
		requestDecision: &Decision{
			Action:   ActionAllow,
			Severity: SeverityLow,
			Findings: []Finding{{Type: "info", Severity: SeverityLow, Match: "ok"}},
		},
	})
	p.Register(&mockInspector{
		name: "allow2",
		requestDecision: &Decision{
			Action:   ActionAllow,
			Severity: SeverityMedium,
			Findings: []Finding{{Type: "info2", Severity: SeverityMedium, Match: "ok2"}},
		},
	})

	d, err := p.InspectRequest(context.Background(), &Payload{Text: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionAllow {
		t.Errorf("expected allow, got %s", d.Action)
	}
	if d.Severity != SeverityMedium {
		t.Errorf("expected medium severity, got %s", d.Severity)
	}
	if len(d.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(d.Findings))
	}
}

func TestFlagContinues(t *testing.T) {
	p := NewPipeline()
	p.Register(&mockInspector{
		name: "flagger",
		requestDecision: &Decision{
			Action:   ActionFlag,
			Severity: SeverityMedium,
			Findings: []Finding{{Type: "flag", Severity: SeverityMedium, Match: "suspicious"}},
		},
	})
	p.Register(&mockInspector{
		name: "allower",
		requestDecision: &Decision{
			Action:   ActionAllow,
			Severity: SeverityLow,
			Findings: []Finding{{Type: "ok", Severity: SeverityLow, Match: "fine"}},
		},
	})

	d, err := p.InspectRequest(context.Background(), &Payload{Text: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionFlag {
		t.Errorf("expected flag (worst non-block action tracked), got %s", d.Action)
	}
	if len(d.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(d.Findings))
	}
}

func TestSanitizeContinues(t *testing.T) {
	p := NewPipeline()
	p.Register(&mockInspector{
		name: "sanitizer",
		requestDecision: &Decision{
			Action:   ActionSanitize,
			Severity: SeverityMedium,
			Findings: []Finding{{Type: "pii", Severity: SeverityMedium, Match: "email"}},
		},
	})
	p.Register(&mockInspector{
		name: "allower",
		requestDecision: &Decision{
			Action:   ActionAllow,
			Severity: SeverityLow,
		},
	})

	d, err := p.InspectRequest(context.Background(), &Payload{Text: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionSanitize {
		t.Errorf("expected sanitize (worst non-block action tracked), got %s", d.Action)
	}
	if len(d.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(d.Findings))
	}
}

func TestResponseInspection(t *testing.T) {
	p := NewPipeline()
	p.Register(&mockInspector{
		name: "response-checker",
		responseDecision: &Decision{
			Action:   ActionBlock,
			Reason:   "sensitive data in response",
			Severity: SeverityCritical,
			Findings: []Finding{{Type: "leak", Severity: SeverityCritical, Match: "secret"}},
		},
	})

	d, err := p.InspectResponse(context.Background(), &Payload{Text: "response with secret"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionBlock {
		t.Errorf("expected block, got %s", d.Action)
	}
	if d.Severity != SeverityCritical {
		t.Errorf("expected critical severity, got %s", d.Severity)
	}
}

func TestAggregatesFindings(t *testing.T) {
	p := NewPipeline()
	p.Register(&mockInspector{
		name: "first",
		requestDecision: &Decision{
			Action:   ActionFlag,
			Severity: SeverityLow,
			Findings: []Finding{
				{Type: "a", Severity: SeverityLow, Match: "m1"},
				{Type: "b", Severity: SeverityLow, Match: "m2"},
			},
		},
	})
	p.Register(&mockInspector{
		name: "second",
		requestDecision: &Decision{
			Action:   ActionFlag,
			Severity: SeverityHigh,
			Findings: []Finding{
				{Type: "c", Severity: SeverityHigh, Match: "m3"},
			},
		},
	})

	d, err := p.InspectRequest(context.Background(), &Payload{Text: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionFlag {
		t.Errorf("expected flag (worst non-block action), got %s", d.Action)
	}
	if len(d.Findings) != 3 {
		t.Errorf("expected 3 aggregated findings, got %d", len(d.Findings))
	}
	if d.Severity != SeverityHigh {
		t.Errorf("expected high severity (highest), got %s", d.Severity)
	}
}

func TestInspectorError(t *testing.T) {
	p := NewPipeline()
	p.Register(&mockInspector{
		name:       "error-inspector",
		requestErr: errors.New("inspection failed"),
	})

	_, err := p.InspectRequest(context.Background(), &Payload{Text: "test"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestNilDecisionSkipped(t *testing.T) {
	p := NewPipeline()
	p.Register(&mockInspector{
		name:            "nil-returner",
		requestDecision: nil,
	})
	p.Register(&mockInspector{
		name: "allower",
		requestDecision: &Decision{
			Action:   ActionAllow,
			Severity: SeverityLow,
			Findings: []Finding{{Type: "ok", Severity: SeverityLow, Match: "fine"}},
		},
	})

	d, err := p.InspectRequest(context.Background(), &Payload{Text: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionAllow {
		t.Errorf("expected allow, got %s", d.Action)
	}
	if len(d.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(d.Findings))
	}
}

// TestFlagActionTracked — flag action is preserved in final decision, not collapsed to allow.
func TestFlagActionTracked(t *testing.T) {
	p := NewPipeline()
	p.Register(&mockInspector{
		name: "flagger",
		requestDecision: &Decision{
			Action:   ActionFlag,
			Reason:   "suspicious pattern",
			Severity: SeverityMedium,
			Findings: []Finding{{Type: "test", Severity: SeverityMedium, Match: "pattern"}},
		},
	})

	d, err := p.InspectRequest(context.Background(), &Payload{Text: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionFlag {
		t.Errorf("expected flag action to be tracked, got %s", d.Action)
	}
	if d.Reason != "suspicious pattern" {
		t.Errorf("expected reason 'suspicious pattern', got %q", d.Reason)
	}
	if d.InspectorName != "flagger" {
		t.Errorf("expected inspector name 'flagger', got %q", d.InspectorName)
	}
}

// TestSanitizeOverridesFlag — sanitize is worse than flag, so sanitize wins.
func TestSanitizeOverridesFlag(t *testing.T) {
	p := NewPipeline()
	p.Register(&mockInspector{
		name: "flagger",
		requestDecision: &Decision{
			Action:   ActionFlag,
			Reason:   "flagged",
			Severity: SeverityLow,
		},
	})
	p.Register(&mockInspector{
		name: "sanitizer",
		requestDecision: &Decision{
			Action:   ActionSanitize,
			Reason:   "needs sanitization",
			Severity: SeverityMedium,
		},
	})

	d, err := p.InspectRequest(context.Background(), &Payload{Text: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionSanitize {
		t.Errorf("expected sanitize (overrides flag), got %s", d.Action)
	}
	if d.InspectorName != "sanitizer" {
		t.Errorf("expected inspector name 'sanitizer', got %q", d.InspectorName)
	}
}

// TestContentRateLimiterRecordFlagOnPipelineFlag — when a flag decision occurs,
// ContentRateLimiter.RecordFlag is called automatically.
func TestContentRateLimiterRecordFlagOnPipelineFlag(t *testing.T) {
	p := NewPipeline()

	rl := NewContentRateLimiter(ContentRateLimitConfig{
		Enabled:           true,
		MaxCharsPerMinute: 100000,
		MaxFlagsPerMinute: 3,
		Window:            time.Minute,
	})
	p.Register(rl)

	p.Register(&mockInspector{
		name: "flagger",
		requestDecision: &Decision{
			Action:   ActionFlag,
			Reason:   "suspicious",
			Severity: SeverityMedium,
		},
	})

	payload := &Payload{Text: "test", UserID: "flaguser"}

	// Send 3 requests — each triggers a flag, RecordFlag should be called
	for i := 0; i < 3; i++ {
		_, err := p.InspectRequest(context.Background(), payload)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
	}

	// 4th request: ContentRateLimiter should block due to 3 flags accumulated
	d, err := p.InspectRequest(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != ActionBlock {
		t.Errorf("expected block after flag limit exceeded, got %s: %s", d.Action, d.Reason)
	}
}

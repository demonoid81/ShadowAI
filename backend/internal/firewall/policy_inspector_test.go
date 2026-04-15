package firewall

import (
	"context"
	"testing"
)

func TestPolicyInspector_NilEngine(t *testing.T) {
	inspector := NewPolicyInspector(nil)
	payload := &Payload{Text: "Any text here", Model: "gpt-4"}

	decision, err := inspector.InspectRequest(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != ActionAllow {
		t.Errorf("expected ActionAllow for nil engine, got %s", decision.Action)
	}
}

func TestPolicyInspector_ResponseSkipped(t *testing.T) {
	inspector := NewPolicyInspector(nil)
	payload := &Payload{Text: "Some response text"}

	decision, err := inspector.InspectResponse(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != ActionAllow {
		t.Errorf("expected ActionAllow for response, got %s", decision.Action)
	}
}

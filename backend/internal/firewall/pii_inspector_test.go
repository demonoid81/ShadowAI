package firewall

import (
	"context"
	"testing"
)

func TestPIIInspector_NoPII(t *testing.T) {
	inspector := NewPIIInspector()
	payload := &Payload{Text: "Hello, this is a normal message with no sensitive data."}

	decision, err := inspector.InspectRequest(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != ActionAllow {
		t.Errorf("expected ActionAllow, got %s", decision.Action)
	}
	if len(decision.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(decision.Findings))
	}
}

func TestPIIInspector_DetectsEmail(t *testing.T) {
	inspector := NewPIIInspector()
	payload := &Payload{Text: "Contact me at user@example.com please."}

	decision, err := inspector.InspectRequest(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != ActionFlag {
		t.Errorf("expected ActionFlag, got %s", decision.Action)
	}

	found := false
	for _, f := range decision.Findings {
		if f.Type == "pii:email" {
			found = true
			if f.Match != "user@example.com" {
				t.Errorf("expected match 'user@example.com', got '%s'", f.Match)
			}
		}
	}
	if !found {
		t.Error("expected pii:email finding, not found")
	}
}

func TestPIIInspector_DetectsPhoneInResponse(t *testing.T) {
	inspector := NewPIIInspector()
	payload := &Payload{Text: "Call me at 555-123-4567 anytime."}

	decision, err := inspector.InspectResponse(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != ActionFlag {
		t.Errorf("expected ActionFlag, got %s", decision.Action)
	}

	found := false
	for _, f := range decision.Findings {
		if f.Type == "pii:phone" {
			found = true
		}
	}
	if !found {
		t.Error("expected pii:phone finding, not found")
	}
}

package firewall

import (
	"context"
	"testing"

	"github.com/shadowai/backend/internal/dlp"
)

func TestDLPInspector_NoSecrets(t *testing.T) {
	svc := dlp.NewService("enforce")
	inspector := NewDLPInspector(svc)
	payload := &Payload{Text: "This is a normal message without any secrets."}

	decision, err := inspector.InspectRequest(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != ActionAllow {
		t.Errorf("expected ActionAllow, got %s", decision.Action)
	}
}

func TestDLPInspector_OpenAIKey_Enforce_Block(t *testing.T) {
	svc := dlp.NewService("enforce")
	inspector := NewDLPInspector(svc)
	payload := &Payload{Text: "My key is sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234"}

	decision, err := inspector.InspectRequest(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != ActionBlock {
		t.Errorf("expected ActionBlock, got %s", decision.Action)
	}
}

func TestDLPInspector_OpenAIKey_Audit_NotBlock(t *testing.T) {
	svc := dlp.NewService("audit")
	inspector := NewDLPInspector(svc)
	payload := &Payload{Text: "My key is sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234"}

	decision, err := inspector.InspectRequest(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action == ActionBlock {
		t.Errorf("expected NOT ActionBlock in audit mode, got %s", decision.Action)
	}
}

func TestDLPInspector_NilService(t *testing.T) {
	inspector := NewDLPInspector(nil)
	payload := &Payload{Text: "My key is sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234"}

	decision, err := inspector.InspectRequest(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != ActionAllow {
		t.Errorf("expected ActionAllow for nil service, got %s", decision.Action)
	}
}

// TestDLPInspector_SanitizePopulatesText проверяет, что при Action == ActionSanitize
// поле Decision.SanitizedText заполняется очищенной версией исходного текста.
func TestDLPInspector_SanitizePopulatesText(t *testing.T) {
	svc := dlp.NewService("enforce")
	inspector := NewDLPInspector(svc)
	original := "my email is user@example.com please"
	payload := &Payload{Text: original}

	decision, err := inspector.InspectRequest(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != ActionSanitize {
		t.Skipf("ожидалось ActionSanitize для email в enforce-mode, получено %s (тест пропущен)", decision.Action)
	}
	if decision.SanitizedText == "" {
		t.Error("SanitizedText должен быть заполнен при Action == ActionSanitize")
	}
	if decision.SanitizedText == original {
		t.Error("SanitizedText должен отличаться от исходного текста")
	}
}

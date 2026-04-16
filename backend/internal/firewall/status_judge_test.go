package firewall

import (
	"strings"
	"testing"
	"time"
)

// TestStatus_JudgeInfoVisibleForJudgeBackedInspectors — PR-2: когда
// инспектор сконфигурирован с judge, status API должен это показать.
// Без этого оператор не может подтвердить per-inspector judge setup
// на running системе.
func TestStatus_JudgeInfoVisibleForJudgeBackedInspectors(t *testing.T) {
	judge := NewJudge(JudgeConfig{
		Provider: "ollama",
		Model:    "llama3",
		Endpoint: "http://localhost:11434",
		Timeout:  7 * time.Second,
		Enabled:  true,
	})

	p := NewPipeline()
	p.Register(NewPromptInjectionInspector(PromptInjectionConfig{Enabled: true}, judge))
	p.Register(NewJailbreakInspector(JailbreakConfig{Enabled: true}, judge))
	p.Register(NewContentModerationInspector(ContentModerationConfig{Enabled: true}, judge))
	// Инспекторы без judge (pipeline-level) — не должны иметь JudgeInfo.
	p.Register(NewOutputValidationInspector(OutputValidationConfig{Enabled: true}))
	p.Register(NewSemanticInspector(SemanticConfig{Enabled: true}))

	statuses := p.Status()

	var seenJudgeBacked int
	for _, s := range statuses {
		switch s.Name {
		case "prompt_injection", "jailbreak", "content_moderation":
			if s.JudgeInfo == nil {
				t.Errorf("inspector %q должен иметь JudgeInfo (судья сконфигурирован)", s.Name)
				continue
			}
			if s.JudgeInfo.Provider != "ollama" {
				t.Errorf("inspector %q: Provider = %q, want ollama", s.Name, s.JudgeInfo.Provider)
			}
			if s.JudgeInfo.Model != "llama3" {
				t.Errorf("inspector %q: Model = %q, want llama3", s.Name, s.JudgeInfo.Model)
			}
			if s.JudgeInfo.TimeoutSeconds != 7.0 {
				t.Errorf("inspector %q: TimeoutSeconds = %g, want 7.0", s.Name, s.JudgeInfo.TimeoutSeconds)
			}
			if !s.JudgeInfo.Enabled {
				t.Errorf("inspector %q: JudgeInfo.Enabled должно быть true", s.Name)
			}
			seenJudgeBacked++
		case "output_validation", "semantic":
			if s.JudgeInfo != nil {
				t.Errorf("inspector %q без judge не должен иметь JudgeInfo", s.Name)
			}
		}
	}
	if seenJudgeBacked != 3 {
		t.Errorf("ожидалось 3 judge-backed inspector в status, got %d", seenJudgeBacked)
	}
}

// TestStatus_JudgeInfoAPIKeyNotLeaked — APIKey должен быть sanitized,
// иначе /proxy/firewall/status утекает credentials в UI.
func TestStatus_JudgeInfoAPIKeyNotLeaked(t *testing.T) {
	judge := NewJudge(JudgeConfig{
		Provider: "openai",
		Model:    "gpt-4",
		APIKey:   "sk-super-secret-key-do-not-leak",
		Timeout:  5 * time.Second,
		Enabled:  true,
	})
	p := NewPipeline()
	p.Register(NewPromptInjectionInspector(PromptInjectionConfig{Enabled: true}, judge))

	statuses := p.Status()
	for _, s := range statuses {
		if s.JudgeInfo == nil {
			continue
		}
		// Никакое поле не должно содержать секрет.
		joined := s.JudgeInfo.Provider + s.JudgeInfo.Model
		if strings.Contains(joined, "sk-super-secret") {
			t.Errorf("APIKey leak в JudgeInfo: %+v", s.JudgeInfo)
		}
	}
}

// TestStatus_InspectorsWithoutJudgeHaveNoJudgeInfo — инспекторы,
// которые не принимают judge (OutputValidation, ContentRateLimiter,
// MultiTurn, Semantic, PII, DLP, Policy), не должны иметь JudgeInfo.
func TestStatus_InspectorsWithoutJudgeHaveNoJudgeInfo(t *testing.T) {
	p := NewPipeline()
	p.Register(&PIIInspector{})
	p.Register(NewOutputValidationInspector(OutputValidationConfig{Enabled: true}))
	p.Register(NewContentRateLimiter(ContentRateLimitConfig{Enabled: true}))
	p.Register(NewMultiTurnInspector(MultiTurnConfig{Enabled: true}))
	p.Register(NewSemanticInspector(SemanticConfig{Enabled: true}))

	for _, s := range p.Status() {
		if s.JudgeInfo != nil {
			t.Errorf("inspector %q: JudgeInfo не должен быть установлен для non-judge инспектора", s.Name)
		}
	}
}

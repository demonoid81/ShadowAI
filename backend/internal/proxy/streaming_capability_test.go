package proxy

import (
	"testing"

	"github.com/shadowai/backend/internal/firewall"
)

func TestDecideStreamingCapability_NilPipeline_Incremental(t *testing.T) {
	d := DecideStreamingCapability(nil)
	if d.IsFallback() {
		t.Errorf("nil pipeline: fallback=%v, want incremental", d)
	}
}

func TestDecideStreamingCapability_EmptyPipeline_Incremental(t *testing.T) {
	p := firewall.NewPipeline()
	d := DecideStreamingCapability(p)
	if d.IsFallback() {
		t.Errorf("empty pipeline: fallback=%v, want incremental", d)
	}
}

func TestDecideStreamingCapability_PatternInspectorsOnly_Incremental(t *testing.T) {
	// Pattern-based inspector'ы (наш mock без judge) → incremental.
	p := firewall.NewPipeline()
	p.Register(alwaysFlagResponseInspector{})
	d := DecideStreamingCapability(p)
	if d.IsFallback() {
		t.Errorf("pattern-only pipeline: fallback=%v", d)
	}
}

// TestDecideStreamingCapability_CMWithJudge_Fallback — ключевой
// F7.2 guardrail (RFC §12.6). Реальный firewall.ContentModerationInspector
// с non-nil Judge, чей config.Enabled=true → capability = fallback.
func TestDecideStreamingCapability_CMWithJudge_Fallback(t *testing.T) {
	// Judge с Enabled=true. Endpoint не нужен — мы не вызываем
	// Evaluate в этом тесте, только Config() для статуса.
	judge := firewall.NewJudge(firewall.JudgeConfig{
		Enabled:  true,
		Provider: "test",
		Model:    "test-model",
	})
	cm := firewall.NewContentModerationInspector(firewall.ContentModerationConfig{
		Enabled:        true,
		JudgeThreshold: 0.3,
	}, judge)

	p := firewall.NewPipeline()
	p.Register(cm)

	d := DecideStreamingCapability(p)
	if !d.IsFallback() {
		t.Fatalf("CM+judge.Enabled=true: expected fallback, got %+v", d)
	}
	if d.Reason != FallbackReasonJudgeInspector {
		t.Errorf("fallback reason = %q, want %q", d.Reason, FallbackReasonJudgeInspector)
	}
}

// TestDecideStreamingCapability_CMWithoutJudge_Incremental —
// content_moderation без judge работает на heuristic и совместим с
// incremental.
func TestDecideStreamingCapability_CMWithoutJudge_Incremental(t *testing.T) {
	cm := firewall.NewContentModerationInspector(firewall.ContentModerationConfig{
		Enabled:        true,
		JudgeThreshold: 0.0, // эффективно выключает judge branch
	}, nil /* judge=nil */)

	p := firewall.NewPipeline()
	p.Register(cm)

	d := DecideStreamingCapability(p)
	if d.IsFallback() {
		t.Errorf("CM без judge: fallback=%v, want incremental", d)
	}
}

// TestDecideStreamingCapability_CMWithJudgeDisabled_Incremental —
// если judge registered но config.Enabled=false, Evaluate сразу
// возвращает не-threat без upstream call (см. judge.go). Это тоже
// incremental-safe по RFC §12.6.
func TestDecideStreamingCapability_CMWithJudgeDisabled_Incremental(t *testing.T) {
	judge := firewall.NewJudge(firewall.JudgeConfig{
		Enabled:  false, // ключевой case
		Provider: "test",
	})
	cm := firewall.NewContentModerationInspector(firewall.ContentModerationConfig{
		Enabled:        true,
		JudgeThreshold: 0.3,
	}, judge)

	p := firewall.NewPipeline()
	p.Register(cm)

	d := DecideStreamingCapability(p)
	if d.IsFallback() {
		t.Errorf("CM+judge.Enabled=false: fallback=%v, want incremental (RFC §12.6)", d)
	}
}

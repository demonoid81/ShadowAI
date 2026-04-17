package firewallbench

import (
	"context"
	"strings"
	"testing"
)

// detectAlways/detectNever/detectKeyword — детерминированные "инспекторы"
// для тестирования runner-логики без зависимости от firewall пакета.
func detectAlways(_ context.Context, _ string) bool { return true }
func detectNever(_ context.Context, _ string) bool  { return false }
func detectKeyword(kw string) DetectFunc {
	return func(_ context.Context, text string) bool {
		return strings.Contains(text, kw)
	}
}

func mkExamples(label string, texts ...string) []Example {
	out := make([]Example, len(texts))
	for i, t := range texts {
		out[i] = Example{ID: label + "-" + t, Label: label, Text: t}
	}
	return out
}

// TestRun_PerfectDetector — detectKeyword("BAD") матчит все positive и
// ни одного negative → TP=3, FN=0, FP=0, TN=3.
func TestRun_PerfectDetector(t *testing.T) {
	pos := mkExamples("positive", "BAD1", "BAD2", "BAD3")
	neg := mkExamples("negative", "hello", "world", "howdy")

	r := Run(context.Background(), "stub", detectKeyword("BAD"), pos, neg)
	if r.Metrics.TP != 3 || r.Metrics.FN != 0 || r.Metrics.FP != 0 || r.Metrics.TN != 3 {
		t.Errorf("unexpected counts: %+v", r.Metrics)
	}
	if r.Metrics.Precision != 1.0 || r.Metrics.Recall != 1.0 {
		t.Errorf("precision/recall = %.2f/%.2f, want 1.0/1.0", r.Metrics.Precision, r.Metrics.Recall)
	}
	if r.Inspector != "stub" {
		t.Errorf("Inspector = %q, want stub", r.Inspector)
	}
}

// TestRun_AlwaysFires — детектор, который всегда возвращает true:
// TP=Npos, FP=Nneg, FN=0, TN=0. Precision падает в Npos/(Npos+Nneg).
func TestRun_AlwaysFires(t *testing.T) {
	pos := mkExamples("positive", "a", "b", "c")
	neg := mkExamples("negative", "1", "2")

	r := Run(context.Background(), "always", detectAlways, pos, neg)
	if r.Metrics.TP != 3 || r.Metrics.FP != 2 || r.Metrics.FN != 0 || r.Metrics.TN != 0 {
		t.Errorf("unexpected counts: %+v", r.Metrics)
	}
	// Precision = 3/5 = 0.6
	if !approxEq(r.Metrics.Precision, 0.6) {
		t.Errorf("Precision = %.4f, want 0.6", r.Metrics.Precision)
	}
	// Recall = 3/3 = 1.0
	if !approxEq(r.Metrics.Recall, 1.0) {
		t.Errorf("Recall = %.4f, want 1.0", r.Metrics.Recall)
	}
}

// TestRun_NeverFires — детектор, молчащий на всё: TP=0, FP=0, FN=Npos, TN=Nneg.
// Precision=0 (защита от div-by-zero: 0/0 должно быть 0, а не NaN).
func TestRun_NeverFires(t *testing.T) {
	pos := mkExamples("positive", "a", "b")
	neg := mkExamples("negative", "1", "2", "3")

	r := Run(context.Background(), "mute", detectNever, pos, neg)
	if r.Metrics.TP != 0 || r.Metrics.FP != 0 || r.Metrics.FN != 2 || r.Metrics.TN != 3 {
		t.Errorf("unexpected counts: %+v", r.Metrics)
	}
	if r.Metrics.Precision != 0.0 || r.Metrics.Recall != 0.0 {
		t.Errorf("mute detector: precision/recall должны быть 0, got %v/%v",
			r.Metrics.Precision, r.Metrics.Recall)
	}
}

// TestRun_EmptyDatasets — оба dataset'а пусты: Metrics всё-равно валиден
// (не NaN), Total()=0. Это sanity-check: CLI никогда не должен падать на
// пустом наборе, только выдать метрики равные нулю.
func TestRun_EmptyDatasets(t *testing.T) {
	r := Run(context.Background(), "empty", detectAlways, nil, nil)
	if r.Metrics.Total() != 0 {
		t.Errorf("Total() = %d, want 0", r.Metrics.Total())
	}
}

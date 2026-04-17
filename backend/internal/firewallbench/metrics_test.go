package firewallbench

import (
	"math"
	"testing"
)

func approxEq(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// TestComputeMetrics_BalancedCase — проверяет базовую формулу
// при сбалансированном наборе (10 positive, 10 negative, 80% правильных).
// Precision = TP/(TP+FP) = 8/(8+2) = 0.8
// Recall    = TP/(TP+FN) = 8/(8+2) = 0.8
// FPR       = FP/(FP+TN) = 2/(2+8) = 0.2
// F1        = 2*P*R/(P+R) = 0.8
func TestComputeMetrics_BalancedCase(t *testing.T) {
	m := Compute(8, 2, 8, 2)
	if !approxEq(m.Precision, 0.8) {
		t.Errorf("Precision = %.4f, want 0.8", m.Precision)
	}
	if !approxEq(m.Recall, 0.8) {
		t.Errorf("Recall = %.4f, want 0.8", m.Recall)
	}
	if !approxEq(m.FPR, 0.2) {
		t.Errorf("FPR = %.4f, want 0.2", m.FPR)
	}
	if !approxEq(m.F1, 0.8) {
		t.Errorf("F1 = %.4f, want 0.8", m.F1)
	}
}

// TestComputeMetrics_PerfectClassifier — 100% правильных
// (TP=10, FP=0, TN=10, FN=0): precision=recall=F1=1.0, FPR=0.0.
func TestComputeMetrics_PerfectClassifier(t *testing.T) {
	m := Compute(10, 0, 10, 0)
	if !approxEq(m.Precision, 1.0) || !approxEq(m.Recall, 1.0) ||
		!approxEq(m.F1, 1.0) || !approxEq(m.FPR, 0.0) {
		t.Errorf("perfect: got %+v", m)
	}
}

// TestComputeMetrics_ZeroDivision — защита от NaN'ов.
// Если инспектор ничего не детектит (TP=0, FP=0) — precision = 0.
// Если нет positive (TP=0, FN=0) — recall = 0.
// Если нет negative (FP=0, TN=0) — FPR = 0.
// F1 при P=R=0 должен быть 0, а не NaN.
func TestComputeMetrics_ZeroDivision(t *testing.T) {
	cases := []struct {
		name           string
		tp, fp, tn, fn int
	}{
		{"detector_never_fires", 0, 0, 10, 10},
		{"no_positives_in_dataset", 0, 5, 5, 0},
		{"no_negatives_in_dataset", 5, 0, 0, 5},
		{"completely_empty", 0, 0, 0, 0},
	}
	for _, c := range cases {
		m := Compute(c.tp, c.fp, c.tn, c.fn)
		for name, v := range map[string]float64{
			"Precision": m.Precision,
			"Recall":    m.Recall,
			"FPR":       m.FPR,
			"F1":        m.F1,
		} {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				t.Errorf("%s: %s = %v — не-число недопустимо (будет ломать JSON-encode)", c.name, name, v)
			}
		}
	}
}

// TestMetrics_Totals — Positives/Negatives/Total helper'ы должны
// корректно считать размер класса и общий N, чтобы dashboard мог
// показывать "8/10 positive detected" без повторного counting.
func TestMetrics_Totals(t *testing.T) {
	m := Compute(8, 2, 7, 3)
	if m.Positives() != 11 {
		t.Errorf("Positives() = %d, want 11 (TP+FN)", m.Positives())
	}
	if m.Negatives() != 9 {
		t.Errorf("Negatives() = %d, want 9 (FP+TN)", m.Negatives())
	}
	if m.Total() != 20 {
		t.Errorf("Total() = %d, want 20", m.Total())
	}
}

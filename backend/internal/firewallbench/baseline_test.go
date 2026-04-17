package firewallbench

import (
	"os"
	"path/filepath"
	"testing"
)

func writeBaseline(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoadBaseline_HappyPath — валидный baseline.json парсится в
// структуру Baseline с заполненными thresholds.
func TestLoadBaseline_HappyPath(t *testing.T) {
	path := writeBaseline(t, `{
		"inspectors": {
			"prompt_injection": {"min_precision": 0.8, "min_recall": 0.7, "max_fpr": 0.1},
			"jailbreak":        {"min_precision": 0.75, "min_recall": 0.6, "max_fpr": 0.15}
		}
	}`)
	b, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	pi, ok := b.Inspectors["prompt_injection"]
	if !ok || pi.MinPrecision != 0.8 || pi.MinRecall != 0.7 || pi.MaxFPR != 0.1 {
		t.Errorf("prompt_injection baseline = %+v", pi)
	}
}

// TestCheckRegression_AboveThresholds — метрики выше baseline →
// no regressions.
func TestCheckRegression_AboveThresholds(t *testing.T) {
	b := &Baseline{Inspectors: map[string]InspectorBaseline{
		"pi": {MinPrecision: 0.8, MinRecall: 0.7, MaxFPR: 0.1},
	}}
	m := Metrics{Precision: 0.9, Recall: 0.8, FPR: 0.05}
	rs := b.CheckRegression("pi", m)
	if len(rs) != 0 {
		t.Errorf("want 0 regressions, got %d: %+v", len(rs), rs)
	}
}

// TestCheckRegression_PrecisionBelow — precision ниже min_precision →
// regression с корректным Field и Actual.
func TestCheckRegression_PrecisionBelow(t *testing.T) {
	b := &Baseline{Inspectors: map[string]InspectorBaseline{
		"pi": {MinPrecision: 0.8, MinRecall: 0.7, MaxFPR: 0.1},
	}}
	m := Metrics{Precision: 0.75, Recall: 0.8, FPR: 0.05}
	rs := b.CheckRegression("pi", m)
	if len(rs) != 1 || rs[0].Field != "precision" {
		t.Fatalf("want 1 precision regression, got %+v", rs)
	}
	if rs[0].Threshold != 0.8 || rs[0].Actual != 0.75 {
		t.Errorf("regression values: %+v", rs[0])
	}
}

// TestCheckRegression_FPRAbove — FPR выше max_fpr → regression (seмантика
// обратная: для FPR плохо когда выше).
func TestCheckRegression_FPRAbove(t *testing.T) {
	b := &Baseline{Inspectors: map[string]InspectorBaseline{
		"pi": {MinPrecision: 0.5, MinRecall: 0.5, MaxFPR: 0.1},
	}}
	m := Metrics{Precision: 0.9, Recall: 0.9, FPR: 0.25}
	rs := b.CheckRegression("pi", m)
	if len(rs) != 1 || rs[0].Field != "fpr" {
		t.Fatalf("want 1 fpr regression, got %+v", rs)
	}
}

// TestCheckRegression_MultipleViolations — сразу несколько метрик ниже
// порога должны все попасть в отчёт (иначе оператор fix'нет одну и не
// заметит вторую).
func TestCheckRegression_MultipleViolations(t *testing.T) {
	b := &Baseline{Inspectors: map[string]InspectorBaseline{
		"pi": {MinPrecision: 0.9, MinRecall: 0.9, MaxFPR: 0.05},
	}}
	m := Metrics{Precision: 0.5, Recall: 0.5, FPR: 0.5}
	rs := b.CheckRegression("pi", m)
	if len(rs) != 3 {
		t.Errorf("want 3 regressions (precision+recall+fpr), got %d: %+v", len(rs), rs)
	}
}

// TestCheckRegression_UnknownInspector — если инспектора нет в baseline,
// возвращается 0 regressions (не error). Это позволяет CLI запускаться
// с новым инспектором до того, как ему добавили baseline.
// Опертор явно увидит "no baseline" в выводе и создаст его в следующем PR.
func TestCheckRegression_UnknownInspector(t *testing.T) {
	b := &Baseline{Inspectors: map[string]InspectorBaseline{}}
	rs := b.CheckRegression("new_inspector", Metrics{Precision: 0.5, Recall: 0.5, FPR: 0.5})
	if len(rs) != 0 {
		t.Errorf("unknown inspector: want 0 regressions, got %+v", rs)
	}
}

// TestBaseline_HasBaseline — helper чтобы CLI мог явно сообщить
// "no baseline for inspector X". Используется для warning'ов в отчёте.
func TestBaseline_HasBaseline(t *testing.T) {
	b := &Baseline{Inspectors: map[string]InspectorBaseline{
		"pi": {MinPrecision: 0.8},
	}}
	if !b.HasInspector("pi") {
		t.Error("pi должен присутствовать")
	}
	if b.HasInspector("missing") {
		t.Error("missing не должен присутствовать")
	}
}

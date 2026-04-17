package embedding

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// normalizedPair — два ортогональных 2D-нормализованных вектора для
// happy-path тестов.
func normalizedPair() ([]float64, []float64) {
	return []float64{1.0, 0.0}, []float64{0.0, 1.0}
}

// TestLoadCorpus_HappyPath — валидный manifest парсится, items
// присутствуют.
func TestLoadCorpus_HappyPath(t *testing.T) {
	v1, v2 := normalizedPair()
	p := writeJSON(t, t.TempDir(), "corpus.json", map[string]any{
		"version":      1,
		"provider":     "ollama",
		"model":        "nomic-embed-text",
		"dimension":    2,
		"normalized":   true,
		"generated_at": time.Now().Format(time.RFC3339),
		"items": []map[string]any{
			{"id": "pi-001", "category": "prompt_injection", "text": "ignore previous", "embedding": v1},
			{"id": "jb-001", "category": "jailbreak", "text": "dan mode", "embedding": v2},
		},
	})

	c, err := LoadCorpus(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Provider != "ollama" || c.Model != "nomic-embed-text" || c.Dimension != 2 {
		t.Errorf("corpus metadata = %+v", c)
	}
	if len(c.Items) != 2 {
		t.Errorf("items len = %d, want 2", len(c.Items))
	}
}

// TestLoadCorpus_RejectsUnknownVersion — forward-compat guard: если
// version > известной, отказываемся грузить (вместо silent skip полей).
func TestLoadCorpus_RejectsUnknownVersion(t *testing.T) {
	p := writeJSON(t, t.TempDir(), "c.json", map[string]any{
		"version": 99, "provider": "ollama", "model": "m",
		"dimension": 2, "normalized": true, "items": []any{},
	})
	_, err := LoadCorpus(p)
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("want version error, got %v", err)
	}
}

// TestLoadCorpus_RejectsMismatchDimension — item.embedding длины,
// отличной от corpus.dimension, — ошибка. Без этой проверки runtime
// cosine выдал бы мусор для inconsistent items.
func TestLoadCorpus_RejectsMismatchDimension(t *testing.T) {
	p := writeJSON(t, t.TempDir(), "c.json", map[string]any{
		"version": 1, "provider": "ollama", "model": "m",
		"dimension": 2, "normalized": true,
		"items": []map[string]any{
			{"id": "x", "category": "c", "text": "t", "embedding": []float64{1.0, 0.0, 0.5}}, // 3-D в 2-D corpus
		},
	})
	_, err := LoadCorpus(p)
	if err == nil || !strings.Contains(err.Error(), "dimension") {
		t.Errorf("want dimension error, got %v", err)
	}
}

// TestLoadCorpus_RejectsNormalizedFalse — сам флаг normalized=false
// отвергается. Hot path (MaxSim) слепо делает dot-product и предполагает
// unit-length векторы; разрешить "нечестный" манифест с флагом false
// значит допустить silent wrong similarity и поломку thresholds.
//
// Регресс-guard для PR-6.0.1: до этого check'а LoadCorpus проверял
// только нормализацию items ПРИ флаге true, но не требовал сам флаг.
func TestLoadCorpus_RejectsNormalizedFalse(t *testing.T) {
	p := writeJSON(t, t.TempDir(), "c.json", map[string]any{
		"version": 1, "provider": "ollama", "model": "m",
		"dimension": 2, "normalized": false, // флаг явно false
		"items": []map[string]any{
			{"id": "x", "category": "c", "text": "t", "embedding": []float64{1.0, 0.0}},
		},
	})
	_, err := LoadCorpus(p)
	if err == nil || !strings.Contains(err.Error(), "normalized") {
		t.Errorf("want normalized=true requirement error, got %v", err)
	}
}

// TestLoadCorpus_RejectsNonNormalized — если manifest.normalized=true,
// но фактически embedding не единичной длины, load fail'ится. Это защищает
// hot path от silent wrong results (cosine ≠ dot-product на ненормальных).
func TestLoadCorpus_RejectsNonNormalized(t *testing.T) {
	p := writeJSON(t, t.TempDir(), "c.json", map[string]any{
		"version": 1, "provider": "ollama", "model": "m",
		"dimension": 2, "normalized": true,
		"items": []map[string]any{
			{"id": "x", "category": "c", "text": "t", "embedding": []float64{3.0, 4.0}}, // norm=5
		},
	})
	_, err := LoadCorpus(p)
	if err == nil || !strings.Contains(err.Error(), "normaliz") {
		t.Errorf("want normalization error, got %v", err)
	}
}

// TestLoadCorpus_EmptyItems — пустой corpus бесполезен. Fail-fast.
func TestLoadCorpus_EmptyItems(t *testing.T) {
	p := writeJSON(t, t.TempDir(), "c.json", map[string]any{
		"version": 1, "provider": "ollama", "model": "m",
		"dimension": 2, "normalized": true,
		"items":      []any{},
	})
	_, err := LoadCorpus(p)
	if err == nil || !strings.Contains(err.Error(), "items") {
		t.Errorf("want empty-items error, got %v", err)
	}
}

// TestCorpus_MaxSim_ExactMatch — запрос, совпадающий с item, даёт
// cosine=1 и возвращает этот item как match.
func TestCorpus_MaxSim_ExactMatch(t *testing.T) {
	v1, v2 := normalizedPair()
	c := &Corpus{
		Dimension:  2,
		Normalized: true,
		Items: []CorpusItem{
			{ID: "a", Category: "pi", Text: "x", Embedding: v1},
			{ID: "b", Category: "jb", Text: "y", Embedding: v2},
		},
	}
	sim, match := c.MaxSim(v1)
	if !approxEq(sim, 1.0) {
		t.Errorf("sim = %f, want 1.0", sim)
	}
	if match == nil || match.ID != "a" {
		t.Errorf("match = %+v, want id=a", match)
	}
}

// TestCorpus_MaxSim_Orthogonal — ортогональные векторы дают cosine=0.
func TestCorpus_MaxSim_Orthogonal(t *testing.T) {
	v1, v2 := normalizedPair()
	c := &Corpus{
		Dimension:  2,
		Normalized: true,
		Items: []CorpusItem{
			{ID: "a", Category: "pi", Text: "x", Embedding: v1},
		},
	}
	sim, match := c.MaxSim(v2) // orthogonal to v1
	if !approxEq(sim, 0.0) {
		t.Errorf("sim = %f, want 0.0", sim)
	}
	if match == nil || match.ID != "a" {
		t.Errorf("max даже для нулевого sim должен вернуть какой-то item, got %+v", match)
	}
}

// TestCorpus_MaxSim_EmptyReturnsZero — пустой items-slice → sim=0, match=nil.
// В production LoadCorpus не допустит такое состояние (EmptyItems test),
// но MaxSim защищён на случай прямого использования.
func TestCorpus_MaxSim_EmptyReturnsZero(t *testing.T) {
	c := &Corpus{Dimension: 2, Items: nil}
	sim, match := c.MaxSim([]float64{1.0, 0.0})
	if !approxEq(sim, 0.0) || match != nil {
		t.Errorf("empty: sim=%f match=%+v, want 0/nil", sim, match)
	}
}

// TestCorpus_MaxSim_DimensionMismatch — вектор другой dimension →
// sim=0, match=nil (избегаем paniс, runtime сам залогирует error).
func TestCorpus_MaxSim_DimensionMismatch(t *testing.T) {
	v1, _ := normalizedPair()
	c := &Corpus{
		Dimension: 2,
		Items:     []CorpusItem{{ID: "a", Embedding: v1}},
	}
	sim, match := c.MaxSim([]float64{1, 0, 0}) // 3-D
	if !approxEq(sim, 0.0) || match != nil {
		t.Errorf("dim mismatch: sim=%f match=%+v, want 0/nil", sim, match)
	}
}

// TestCorpus_MaxSim_MagnitudeInvariantWhenNormalized — вход vector
// уже L2-normalized, items тоже. Проверяем, что math.Sqrt чистой
// формулы действительно равен dot-product (поэтому используем dot-product).
func TestCorpus_MaxSim_MagnitudeInvariantWhenNormalized(t *testing.T) {
	// Два вектора под углом 60 градусов, нормализованные.
	// cos(60°) = 0.5.
	a := []float64{1.0, 0.0}
	b := []float64{math.Cos(math.Pi / 3), math.Sin(math.Pi / 3)}
	c := &Corpus{
		Dimension:  2,
		Normalized: true,
		Items:      []CorpusItem{{ID: "a", Embedding: a}},
	}
	sim, _ := c.MaxSim(b)
	if !approxEq(sim, 0.5) {
		t.Errorf("cos(60°) sim = %f, want 0.5", sim)
	}
}

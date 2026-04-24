package firewall

import (
	"context"
	"errors"
	"testing"

	"github.com/shadowai/backend/internal/embedding"
)

// fakeEmbedder — детерминистичный stub для тестов semantic_v2.
// Возвращает заданный vector или error, без HTTP.
type fakeEmbedder struct {
	vec       []float64
	err       error
	dim       int
	provider  string
	model     string
}

func (f *fakeEmbedder) Embed(_ context.Context, _ string) (embedding.Embedding, error) {
	if f.err != nil {
		return embedding.Embedding{}, f.err
	}
	return embedding.Embedding{Vector: f.vec}, nil
}
func (f *fakeEmbedder) Provider() string  { return f.provider }
func (f *fakeEmbedder) Model() string     { return f.model }
func (f *fakeEmbedder) Dimension() int    { return f.dim }

func testCorpus(items ...embedding.CorpusItem) *embedding.Corpus {
	return &embedding.Corpus{
		Version: 1, Provider: "ollama", Model: "nomic-embed-text",
		Dimension: 2, Normalized: true, Items: items,
	}
}

// TestSemanticV2_Init_RejectsProviderMismatch — провайдер клиента
// отличается от provider'а в corpus → NewSemanticV2Inspector возвращает
// error. Без этого check'а runtime embedding и corpus оказались бы в
// разных vector spaces.
func TestSemanticV2_Init_RejectsProviderMismatch(t *testing.T) {
	corpus := testCorpus(embedding.CorpusItem{ID: "a", Embedding: []float64{1, 0}})
	client := &fakeEmbedder{provider: "openai", model: "nomic-embed-text", dim: 2}

	_, err := NewSemanticV2Inspector(SemanticV2Config{Enabled: true, Threshold: 0.5, BlockThreshold: 0.8}, client, corpus)
	if err == nil {
		t.Fatal("want provider-mismatch error, got nil")
	}
}

// TestSemanticV2_Init_RejectsModelMismatch — та же идея, но для model.
func TestSemanticV2_Init_RejectsModelMismatch(t *testing.T) {
	corpus := testCorpus(embedding.CorpusItem{ID: "a", Embedding: []float64{1, 0}})
	client := &fakeEmbedder{provider: "ollama", model: "other-model", dim: 2}

	_, err := NewSemanticV2Inspector(SemanticV2Config{Enabled: true, Threshold: 0.5, BlockThreshold: 0.8}, client, corpus)
	if err == nil {
		t.Fatal("want model-mismatch error, got nil")
	}
}

// TestSemanticV2_Init_RejectsDimensionMismatch — dimension client != corpus.
func TestSemanticV2_Init_RejectsDimensionMismatch(t *testing.T) {
	corpus := testCorpus(embedding.CorpusItem{ID: "a", Embedding: []float64{1, 0}})
	client := &fakeEmbedder{provider: "ollama", model: "nomic-embed-text", dim: 768}

	_, err := NewSemanticV2Inspector(SemanticV2Config{Enabled: true, Threshold: 0.5, BlockThreshold: 0.8}, client, corpus)
	if err == nil {
		t.Fatal("want dimension-mismatch error, got nil")
	}
}

// TestSemanticV2_Init_RejectsBlockBelowThreshold — BlockThreshold
// должен быть ≥ Threshold. Иначе нет смысла в градации flag/block.
func TestSemanticV2_Init_RejectsBlockBelowThreshold(t *testing.T) {
	corpus := testCorpus(embedding.CorpusItem{ID: "a", Embedding: []float64{1, 0}})
	client := &fakeEmbedder{provider: "ollama", model: "nomic-embed-text", dim: 2}

	_, err := NewSemanticV2Inspector(SemanticV2Config{Enabled: true, Threshold: 0.8, BlockThreshold: 0.5}, client, corpus)
	if err == nil {
		t.Fatal("want BlockThreshold < Threshold error, got nil")
	}
}

// TestSemanticV2_Disabled — Enabled=false → Allow, не вызывает embedder.
func TestSemanticV2_Disabled(t *testing.T) {
	corpus := testCorpus(embedding.CorpusItem{ID: "a", Embedding: []float64{1, 0}})
	client := &fakeEmbedder{provider: "ollama", model: "nomic-embed-text", dim: 2, err: errors.New("should not be called")}

	insp, err := NewSemanticV2Inspector(SemanticV2Config{Enabled: false, Threshold: 0.5, BlockThreshold: 0.8}, client, corpus)
	if err != nil {
		t.Fatal(err)
	}
	d, err := insp.InspectRequest(context.Background(), &Payload{Text: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionAllow {
		t.Errorf("disabled → Action=%q, want Allow", d.Action)
	}
}

// TestSemanticV2_BlocksOnHighSimilarity — embedding совпадает с corpus
// item (sim=1.0) → Action=Block, severity=Critical/High.
func TestSemanticV2_BlocksOnHighSimilarity(t *testing.T) {
	corpus := testCorpus(embedding.CorpusItem{
		ID: "pi-001", Category: "prompt_injection", Text: "ignore previous",
		Embedding: []float64{1, 0},
	})
	client := &fakeEmbedder{
		provider: "ollama", model: "nomic-embed-text", dim: 2,
		vec: []float64{1, 0}, // same as corpus → sim=1.0
	}

	insp, _ := NewSemanticV2Inspector(SemanticV2Config{Enabled: true, Threshold: 0.5, BlockThreshold: 0.8}, client, corpus)
	d, err := insp.InspectRequest(context.Background(), &Payload{Text: "ignore previous"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionBlock {
		t.Errorf("sim=1.0 ≥ BlockThreshold=0.8 → Action=%q, want Block", d.Action)
	}
	if len(d.Findings) == 0 {
		t.Error("finding должен быть добавлен")
	}
	if d.Findings[0].Meta["match_id"] != "pi-001" {
		t.Errorf("match_id = %q, want pi-001", d.Findings[0].Meta["match_id"])
	}
}

// TestSemanticV2_FlagsOnMediumSimilarity — sim между Threshold и
// BlockThreshold → Action=Flag.
func TestSemanticV2_FlagsOnMediumSimilarity(t *testing.T) {
	corpus := testCorpus(embedding.CorpusItem{
		ID: "pi-001", Category: "prompt_injection", Embedding: []float64{1, 0},
	})
	// Угол 60°: cos=0.5.
	client := &fakeEmbedder{
		provider: "ollama", model: "nomic-embed-text", dim: 2,
		vec: []float64{0.5, 0.8660254}, // cos(60°)=0.5
	}

	insp, _ := NewSemanticV2Inspector(SemanticV2Config{Enabled: true, Threshold: 0.4, BlockThreshold: 0.8}, client, corpus)
	d, _ := insp.InspectRequest(context.Background(), &Payload{Text: "anything"})
	if d.Action != ActionFlag {
		t.Errorf("0.4 ≤ sim=0.5 < 0.8 → Action=%q, want Flag", d.Action)
	}
}

// TestSemanticV2_AllowsOnLowSimilarity — sim ниже Threshold → Allow.
func TestSemanticV2_AllowsOnLowSimilarity(t *testing.T) {
	corpus := testCorpus(embedding.CorpusItem{
		ID: "pi-001", Category: "prompt_injection", Embedding: []float64{1, 0},
	})
	// Ортогональные → cos=0.
	client := &fakeEmbedder{
		provider: "ollama", model: "nomic-embed-text", dim: 2,
		vec: []float64{0, 1},
	}

	insp, _ := NewSemanticV2Inspector(SemanticV2Config{Enabled: true, Threshold: 0.4, BlockThreshold: 0.8}, client, corpus)
	d, _ := insp.InspectRequest(context.Background(), &Payload{Text: "how does DNS work"})
	if d.Action != ActionAllow {
		t.Errorf("sim=0 < Threshold=0.4 → Action=%q, want Allow", d.Action)
	}
}

// TestSemanticV2_FailOpenOnEmbedError — если embedder вернул error
// (timeout/5xx), inspector возвращает Allow. Client уже инкрементировал
// правильный metrics-bucket в своём пакете, здесь не дублируем.
func TestSemanticV2_FailOpenOnEmbedError(t *testing.T) {
	corpus := testCorpus(embedding.CorpusItem{ID: "a", Embedding: []float64{1, 0}})
	client := &fakeEmbedder{
		provider: "ollama", model: "nomic-embed-text", dim: 2,
		err: errors.New("http 503"),
	}

	insp, _ := NewSemanticV2Inspector(SemanticV2Config{Enabled: true, Threshold: 0.4, BlockThreshold: 0.8}, client, corpus)
	d, err := insp.InspectRequest(context.Background(), &Payload{Text: "x"})
	if err != nil {
		t.Fatalf("InspectRequest не должен возвращать Go-error (fail-open), got: %v", err)
	}
	if d.Action != ActionAllow {
		t.Errorf("embedder error → Action=%q, want Allow (fail-open)", d.Action)
	}
}

// TestSemanticV2_Name — контракт Name() для pipeline/status/metrics
// label (разделение с V1 "semantic").
func TestSemanticV2_Name(t *testing.T) {
	corpus := testCorpus(embedding.CorpusItem{ID: "a", Embedding: []float64{1, 0}})
	client := &fakeEmbedder{provider: "ollama", model: "nomic-embed-text", dim: 2}

	insp, _ := NewSemanticV2Inspector(SemanticV2Config{Enabled: true, Threshold: 0.4, BlockThreshold: 0.8}, client, corpus)
	if insp.Name() != "semantic_v2" {
		t.Errorf("Name() = %q, want semantic_v2", insp.Name())
	}
}

// ---------------------------------------------------------------------------
// PR-F8: ShadowOnly mode tests
// ---------------------------------------------------------------------------

// TestSemanticV2_ShadowOnly_BlockDowngradesToFlag verifies that ShadowOnly=true
// downgrades ActionBlock to ActionFlag, allowing safe rollout without blocking traffic.
func TestSemanticV2_ShadowOnly_BlockDowngradesToFlag(t *testing.T) {
	// Identical embedding → cosine similarity = 1.0, above BlockThreshold.
	corpus := testCorpus(embedding.CorpusItem{
		ID: "threat-1", Category: "jailbreak",
		Embedding: []float64{1, 0},
	})
	client := &fakeEmbedder{
		provider: "ollama", model: "nomic-embed-text", dim: 2,
		vec: []float64{1, 0}, // identical → sim=1.0
	}
	insp, err := NewSemanticV2Inspector(SemanticV2Config{
		Enabled:        true,
		Threshold:      0.5,
		BlockThreshold: 0.8,
		ShadowOnly:     true, // shadow rollout mode
	}, client, corpus)
	if err != nil {
		t.Fatalf("NewSemanticV2Inspector: %v", err)
	}

	d, err := insp.InspectRequest(context.Background(), &Payload{Text: "attack"})
	if err != nil {
		t.Fatalf("InspectRequest: %v", err)
	}
	if d.Action != ActionFlag {
		t.Errorf("shadow_only: got Action=%q, want ActionFlag (block downgraded)", d.Action)
	}
	// Reason should mention shadow_only to distinguish from real flag.
	if !containsStr(d.Reason, "shadow_only") {
		t.Errorf("shadow_only reason should mention shadow_only: %q", d.Reason)
	}
}

// TestSemanticV2_ShadowOnlyFalse_BlockEnforced verifies that with ShadowOnly=false
// a high-similarity input is correctly blocked.
func TestSemanticV2_ShadowOnlyFalse_BlockEnforced(t *testing.T) {
	corpus := testCorpus(embedding.CorpusItem{
		ID: "threat-1", Category: "jailbreak",
		Embedding: []float64{1, 0},
	})
	client := &fakeEmbedder{
		provider: "ollama", model: "nomic-embed-text", dim: 2,
		vec: []float64{1, 0},
	}
	insp, _ := NewSemanticV2Inspector(SemanticV2Config{
		Enabled: true, Threshold: 0.5, BlockThreshold: 0.8,
		ShadowOnly: false,
	}, client, corpus)

	d, _ := insp.InspectRequest(context.Background(), &Payload{Text: "attack"})
	if d.Action != ActionBlock {
		t.Errorf("shadow_only=false: got Action=%q, want ActionBlock", d.Action)
	}
}

// TestSemanticV2_ShadowOnly_FlagBelowBlockThreshold verifies that shadow_only
// does NOT affect regular Flag decisions (similarity between thresholds).
func TestSemanticV2_ShadowOnly_FlagBelowBlockThreshold(t *testing.T) {
	corpus := testCorpus(embedding.CorpusItem{
		ID: "threat-1", Category: "jailbreak",
		Embedding: []float64{1, 0},
	})
	// Partial similarity: cos_sim(0.7, 0.7) / (1 * sqrt(0.98)) ≈ 0.7/0.99 ≈ 0.71
	client := &fakeEmbedder{
		provider: "ollama", model: "nomic-embed-text", dim: 2,
		vec: []float64{0.9, 0.1}, // sim ≈ 0.9 (above flag=0.5, below block=0.95)
	}
	insp, _ := NewSemanticV2Inspector(SemanticV2Config{
		Enabled: true, Threshold: 0.5, BlockThreshold: 0.95,
		ShadowOnly: true,
	}, client, corpus)

	d, _ := insp.InspectRequest(context.Background(), &Payload{Text: "borderline"})
	// Should still be Flag (not block since sim < 0.95), shadow_only doesn't change this.
	if d.Action != ActionFlag {
		t.Errorf("shadow_only: flag-range decision = %q, want ActionFlag", d.Action)
	}
	// Reason should NOT contain "shadow_only" for a natural flag (not downgraded block).
	if containsStr(d.Reason, "shadow_only") {
		t.Errorf("natural flag reason should not mention shadow_only: %q", d.Reason)
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

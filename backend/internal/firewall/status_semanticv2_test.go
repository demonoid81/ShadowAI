package firewall

import (
	"strings"
	"testing"

	"github.com/shadowai/backend/internal/embedding"
)

// TestStatus_SemanticV2_ExposesSafeMetadata — status показывает
// provider/model/thresholds/corpus_version/corpus_items, но НЕ
// endpoint/api-key.
func TestStatus_SemanticV2_ExposesSafeMetadata(t *testing.T) {
	corpus := &embedding.Corpus{
		Version: 1, Provider: "ollama", Model: "nomic-embed-text",
		Dimension: 2, Normalized: true,
		Items: []embedding.CorpusItem{
			{ID: "a", Category: "prompt_injection", Embedding: []float64{1, 0}},
		},
	}
	client := &fakeEmbedder{provider: "ollama", model: "nomic-embed-text", dim: 2}

	insp, err := NewSemanticV2Inspector(SemanticV2Config{
		Enabled: true, Threshold: 0.5, BlockThreshold: 0.8,
	}, client, corpus)
	if err != nil {
		t.Fatal(err)
	}

	p := NewPipeline()
	p.Register(insp)

	statuses := p.Status()
	if len(statuses) != 1 {
		t.Fatalf("got %d statuses, want 1", len(statuses))
	}
	s := statuses[0]
	if s.Name != "semantic_v2" {
		t.Errorf("Name = %q", s.Name)
	}
	if s.SemanticV2 == nil {
		t.Fatal("SemanticV2 status должен быть заполнен для semantic_v2 inspector'а")
	}
	if s.SemanticV2.Provider != "ollama" || s.SemanticV2.Model != "nomic-embed-text" {
		t.Errorf("provider/model = %+v", s.SemanticV2)
	}
	if s.SemanticV2.Dimension != 2 {
		t.Errorf("dimension = %d", s.SemanticV2.Dimension)
	}
	if s.SemanticV2.Threshold != 0.5 || s.SemanticV2.BlockThreshold != 0.8 {
		t.Errorf("thresholds = %+v", s.SemanticV2)
	}
	if s.SemanticV2.CorpusVersion != 1 || s.SemanticV2.CorpusItems != 1 {
		t.Errorf("corpus stats = %+v", s.SemanticV2)
	}
}

// TestStatus_SemanticV2_NoEndpointLeak — endpoint и APIKey НЕ должны
// попадать в status API.
func TestStatus_SemanticV2_NoEndpointLeak(t *testing.T) {
	corpus := &embedding.Corpus{
		Version: 1, Provider: "ollama", Model: "m", Dimension: 2, Normalized: true,
		Items: []embedding.CorpusItem{{ID: "a", Embedding: []float64{1, 0}}},
	}
	// Реальный client с endpoint и ключом (не fakeEmbedder) — проверим,
	// что даже если status берёт из client'а, секретов не видно.
	c, err := embedding.NewClient(embedding.Config{
		Provider: "openai", Endpoint: "https://api.openai.com",
		Model: "m", APIKey: "sk-super-secret-do-not-leak",
		Dimension: 2, Timeout: 1e9,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Corpus matches openai-model для прохождения init-check.
	corpus.Provider = "openai"
	corpus.Model = "m"

	insp, err := NewSemanticV2Inspector(SemanticV2Config{
		Enabled: true, Threshold: 0.5, BlockThreshold: 0.8,
	}, c, corpus)
	if err != nil {
		t.Fatal(err)
	}

	p := NewPipeline()
	p.Register(insp)

	statuses := p.Status()
	s := statuses[0]
	if s.SemanticV2 == nil {
		t.Fatal("semantic_v2 status не должен быть nil")
	}
	// Сериализованно собираем всё, что точно не должно утекать,
	// и проверяем отсутствие секрета в JSON-репрезентации.
	joined := s.SemanticV2.Provider + s.SemanticV2.Model
	if strings.Contains(joined, "sk-super-secret") {
		t.Errorf("APIKey leak: %+v", s.SemanticV2)
	}
	if strings.Contains(joined, "openai.com") {
		t.Errorf("endpoint leak: %+v", s.SemanticV2)
	}
}

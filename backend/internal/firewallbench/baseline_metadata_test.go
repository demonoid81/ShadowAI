package firewallbench

import "testing"

// TestCheckInspectorMetadata_Match — провайдер/модель/версия corpus
// совпадают с baseline → пустой результат (не-regression).
func TestCheckInspectorMetadata_Match(t *testing.T) {
	b := &Baseline{Inspectors: map[string]InspectorBaseline{
		"semantic_v2": {
			Provider: "ollama", Model: "nomic-embed-text", CorpusVersion: 1,
			MinPrecision: 0.8, MinRecall: 0.5, MaxFPR: 0.1,
		},
	}}
	got := b.CheckInspectorMetadata("semantic_v2", "ollama", "nomic-embed-text", 1)
	if len(got) != 0 {
		t.Errorf("match: want 0 mismatches, got %+v", got)
	}
}

// TestCheckInspectorMetadata_ProviderMismatch — runtime provider != baseline.
func TestCheckInspectorMetadata_ProviderMismatch(t *testing.T) {
	b := &Baseline{Inspectors: map[string]InspectorBaseline{
		"semantic_v2": {Provider: "ollama", Model: "m", CorpusVersion: 1},
	}}
	got := b.CheckInspectorMetadata("semantic_v2", "openai", "m", 1)
	if len(got) != 1 || got[0].Field != "provider" {
		t.Errorf("provider mismatch: got %+v", got)
	}
}

// TestCheckInspectorMetadata_ModelMismatch — model не совпадает.
func TestCheckInspectorMetadata_ModelMismatch(t *testing.T) {
	b := &Baseline{Inspectors: map[string]InspectorBaseline{
		"semantic_v2": {Provider: "ollama", Model: "nomic-embed-text", CorpusVersion: 1},
	}}
	got := b.CheckInspectorMetadata("semantic_v2", "ollama", "all-minilm", 1)
	if len(got) != 1 || got[0].Field != "model" {
		t.Errorf("model mismatch: got %+v", got)
	}
}

// TestCheckInspectorMetadata_CorpusVersionMismatch — corpus_version другой.
func TestCheckInspectorMetadata_CorpusVersionMismatch(t *testing.T) {
	b := &Baseline{Inspectors: map[string]InspectorBaseline{
		"semantic_v2": {Provider: "ollama", Model: "m", CorpusVersion: 1},
	}}
	got := b.CheckInspectorMetadata("semantic_v2", "ollama", "m", 2)
	if len(got) != 1 || got[0].Field != "corpus_version" {
		t.Errorf("corpus_version mismatch: got %+v", got)
	}
	if got[0].Actual != 2 || got[0].Threshold != 1 {
		t.Errorf("cv mismatch numbers: got %+v", got[0])
	}
}

// TestCheckInspectorMetadata_MultipleMismatches — сразу несколько
// расхождений попадают в отчёт (оператор фиксит всё, а не по одному).
func TestCheckInspectorMetadata_MultipleMismatches(t *testing.T) {
	b := &Baseline{Inspectors: map[string]InspectorBaseline{
		"semantic_v2": {Provider: "ollama", Model: "nomic", CorpusVersion: 1},
	}}
	got := b.CheckInspectorMetadata("semantic_v2", "openai", "text-embedding", 2)
	if len(got) != 3 {
		t.Errorf("want 3 mismatches, got %d: %+v", len(got), got)
	}
}

// TestCheckInspectorMetadata_NoMetadataInBaseline — если baseline не
// содержит provider/model/corpus_version (heuristic inspector), check
// проходит без ошибок независимо от runtime-значений.
func TestCheckInspectorMetadata_NoMetadataInBaseline(t *testing.T) {
	b := &Baseline{Inspectors: map[string]InspectorBaseline{
		"prompt_injection": {MinPrecision: 0.8},
	}}
	got := b.CheckInspectorMetadata("prompt_injection", "ollama", "m", 1)
	if len(got) != 0 {
		t.Errorf("heuristic baseline без metadata: want 0, got %+v", got)
	}
}

// TestCheckInspectorMetadata_UnknownInspector — инспектор отсутствует
// в baseline → пусто (не regression, CLI отдельно сообщит "no baseline").
func TestCheckInspectorMetadata_UnknownInspector(t *testing.T) {
	b := &Baseline{Inspectors: map[string]InspectorBaseline{}}
	got := b.CheckInspectorMetadata("new_inspector", "ollama", "m", 1)
	if len(got) != 0 {
		t.Errorf("unknown inspector: want 0, got %+v", got)
	}
}

// TestMetadataFor_ReturnsRecorded — smoke: metadata достаётся как есть.
func TestMetadataFor_ReturnsRecorded(t *testing.T) {
	b := &Baseline{Inspectors: map[string]InspectorBaseline{
		"semantic_v2": {Provider: "openai", Model: "te-3-small", CorpusVersion: 42},
	}}
	p, m, cv := b.MetadataFor("semantic_v2")
	if p != "openai" || m != "te-3-small" || cv != 42 {
		t.Errorf("metadata = (%q, %q, %d)", p, m, cv)
	}
}
